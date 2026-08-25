// dsh-remote-gateway — the gateway HTTP server: login page + session
// enforcement in front of the harness web server, and a transparent
// HTTP/WebSocket reverse proxy to the loopback-bound harness.
//
// Upstream header policy: the gateway is the authentication layer, so it
// rewrites Host and Origin to the loopback upstream authority before
// proxying. The harness's own /api trust fence then sees loopback-same-origin
// traffic (including the privileged configuration-plane methods it pins to
// loopback) while the gateway remains the only network-exposed surface.
// The original authority is preserved in X-Forwarded-Host.
import { createServer, request as httpRequest } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFileSync } from "node:fs";
import { connect as netConnect } from "node:net";
import { loginPageHtml } from "./login-page.js";
import { applyGatewaySettings, loadPrimarySettings, loadUsers, saveCredentialsText, validateTrustedDomainsList, verifyUser } from "./auth.js";

const MAX_BODY_BYTES = 64 * 1024;

/**
 * Paths a browser may fetch without a session: harmless app metadata (PWA
 * manifest, favicon, robots). Browsers fetch these on first load and during
 * PWA install — before login or with a stale session cookie — so gating them
 * only produces 401 console noise. Everything else still requires login.
 */
const PUBLIC_PATHS = new Set([
  "/manifest.webmanifest",
  "/manifest.json",
  "/favicon.svg",
  "/favicon.ico",
  "/robots.txt",
]);

/** Headers that must not be forwarded as-is on either direction of a proxy hop. */
const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "host",
]);

const SECURITY_HEADERS = {
  "cache-control": "no-store",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

function parseCookies(req) {
  const out = new Map();
  const header = req.headers.cookie;
  if (typeof header !== "string") return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name !== "") out.set(name, value);
  }
  return out;
}

/** Read and cap a request body. */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    const finish = (err) => {
      if (done) return;
      done = true;
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("error", onError);
      if (err) reject(err);
      else resolve(Buffer.concat(chunks));
    };
    const onData = (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) return finish(new Error("body too large"));
      chunks.push(chunk);
    };
    const onEnd = () => finish(null);
    const onError = (err) => finish(err);
    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
  });
}

/** Parse form-urlencoded or JSON credentials (plus the redirect target). */
async function parseCredentials(req) {
  const contentType = String(req.headers["content-type"] ?? "").split(";", 1)[0].trim().toLowerCase();
  const body = await readBody(req);
  if (contentType === "application/json") {
    const doc = JSON.parse(body.toString("utf8"));
    return {
      username: String(doc?.username ?? ""),
      password: String(doc?.password ?? ""),
      next: String(doc?.next ?? "/"),
    };
  }
  const params = new URLSearchParams(body.toString("utf8"));
  return {
    username: params.get("username") ?? "",
    password: params.get("password") ?? "",
    next: params.get("next") ?? "/",
  };
}

/** Same-origin relative path only; anything else falls back to "/". */
function safeNext(value) {
  const next = String(value ?? "");
  if (next.startsWith("/") && !next.startsWith("//")) return next;
  return "/";
}

function sendHtml(res, status, html, extraHeaders = {}) {
  if (res.headersSent) return;
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": Buffer.byteLength(html),
    ...SECURITY_HEADERS,
    ...extraHeaders,
  });
  res.end(html);
}

function sendJson(res, status, body) {
  if (res.headersSent) return;
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(data),
    ...SECURITY_HEADERS,
  });
  res.end(data);
}

function redirect(res, location, status = 303) {
  if (res.headersSent) return;
  res.writeHead(status, { location, "cache-control": "no-store" });
  res.end();
}

/**
 * Upstream endpoints that reject ANY forwarding trace on purpose. The
 * dshmarket plugin guards process-control and backup routes with
 * trustedRestartRequest/trustedDownloadRequest (restart.js): the peer must be
 * a direct loopback client, and the presence of `forwarded`,
 * `x-forwarded-for` or `x-real-ip` proves the loopback peer is a proxy. The
 * gateway adds X-Forwarded-For to every proxied request, which would make
 * these endpoints answer 403 "…limited to same-origin loopback requests".
 * For these exact paths the gateway therefore forwards WITHOUT the forwarding
 * trace (Host/Origin are still loopbacked, which is what the same-origin
 * half of those guards checks).
 */
const NO_FORWARDING_PATHS = new Set([
  "/dsh-market/restart",
  "/dsh-market/backup",
  "/dsh-market/self-uninstall",
]);

// ── trusted domains ─────────────────────────────────────────────────────────
// The gateway can restrict which Host/Origin values it serves ("trusted
// domains"). Default is the "*" wildcard: any domain is accepted (the
// historical behavior). A restricted list blocks DNS-rebinding and
// unintended hostname exposure: a request whose Host header (or Origin, when
// present) is not on the list is answered 403 before anything else runs.

/** Split a host[:port] string. IPv6 literals are bracket-normalized: "[::1]:8443" → {name: "::1", port: "8443"}. */
function splitHostPort(value) {
  const text = String(value ?? "");
  if (text.startsWith("[")) {
    const close = text.indexOf("]");
    if (close !== -1) {
      const inner = text.slice(1, close);
      const rest = text.slice(close + 1);
      if (rest === "") return { name: inner, port: null };
      if (rest.startsWith(":") && /^\d+$/.test(rest.slice(1))) return { name: inner, port: rest.slice(1) };
      return { name: text, port: null };
    }
  }
  const colon = text.lastIndexOf(":");
  if (colon > 0 && colon === text.indexOf(":") && /^\d+$/.test(text.slice(colon + 1))) {
    return { name: text.slice(0, colon), port: text.slice(colon + 1) };
  }
  return { name: text, port: null };
}

/**
 * Whether one host[:port] matches one trusted-domain rule.
 * Rules: "*" (anything), "example.com" (exact host, any port),
 * "example.com:8443" (exact host and port), "*.example.com" (subdomains).
 */
export function hostMatchesTrusted(host, rule) {
  const h = splitHostPort(host);
  if (rule === "*") return true;
  const r = splitHostPort(rule);
  if (r.port !== null && h.port !== r.port) return false;
  const hName = h.name.toLowerCase();
  const rName = r.name.toLowerCase();
  if (rName.startsWith("*.")) {
    const suffix = rName.slice(1); // ".example.com"
    return hName.endsWith(suffix) && hName.length > suffix.length;
  }
  return hName === rName;
}

/** Build a host predicate from a trusted-domain list. An empty list denies all. */
export function compileTrustedDomains(rules) {
  const list = (Array.isArray(rules) ? rules : [String(rules ?? "")])
    .map((rule) => String(rule).trim())
    .filter((rule) => rule !== "");
  return (host) => list.some((rule) => hostMatchesTrusted(host, rule));
}

/** Parse a comma-separated trusted-domains string into a rule list. */
export function parseTrustedDomainsList(text) {
  return String(text ?? "")
    .split(",")
    .map((rule) => rule.trim())
    .filter((rule) => rule !== "");
}

/** Build the upstream request headers: hop-by-hop stripped, authority loopbacked. */
function upstreamHeaders(req, upstream, secure = false, noForwarding = false) {
  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower)) continue;
    if (noForwarding && (lower === "forwarded" || lower === "x-forwarded-for" || lower === "x-real-ip")) continue;
    headers[lower] = value;
  }
  const authority = `${upstream.host}:${String(upstream.port)}`;
  headers.host = authority;
  if (headers.origin !== undefined) headers.origin = `http://${authority}`;
  const clientIp = req.socket.remoteAddress ?? "";
  if (!noForwarding) {
    headers["x-forwarded-for"] = headers["x-forwarded-for"] !== undefined
      ? `${headers["x-forwarded-for"]}, ${clientIp}`
      : clientIp;
  }
  headers["x-forwarded-proto"] = secure ? "https" : "http";
  headers["x-forwarded-host"] = String(req.headers.host ?? authority);
  return headers;
}

/**
 * Marker the gateway injects into every proxied HTML document. The harness
 * client derives `ctx.connection.isLoopback` from the page location, which is
 * false for remote access — that disables the settings UI ("settings are
 * unavailable in this browser", the provider directory fails to load).
 *
 * This marker script is spliced in right after <head>, i.e. BEFORE any of the
 * shell's boot scripts, and the served @deepseek-ai/dsh-client-connection
 * client bundle is patched (scripts/patch-dsh-client.mjs; the dev watcher
 * re-applies it automatically) so that the marker counts as loopback trust:
 * `isLoopback` becomes true on gateway-served pages. The harness /api trust
 * fence then accepts the settings RPCs because the gateway rewrites Host and
 * Origin to the loopback authority anyway.
 */
const GATEWAY_MARKER_SCRIPT = "<script>window.__DSH_AUTH_GATEWAY__=true;</script>";
const GATEWAY_MARKER_KEY = "__DSH_AUTH_GATEWAY__";
const MAX_HTML_BUFFER_BYTES = 4 * 1024 * 1024;

/** Insert the gateway trust marker into an HTML body (idempotent). */
function injectGatewayMarker(body) {
  const html = body.toString("utf8");
  if (html.includes(GATEWAY_MARKER_KEY)) return body;
  const open = /<head(?:\s[^>]*)?>/i.exec(html);
  if (open !== null) {
    const at = open.index + open[0].length;
    return Buffer.from(html.slice(0, at) + GATEWAY_MARKER_SCRIPT + html.slice(at), "utf8");
  }
  return Buffer.from(GATEWAY_MARKER_SCRIPT + html, "utf8");
}

/**
 * Rewrite a session.create RPC for an account with a workDir restriction:
 * the requested workspaceId is replaced by cwd=<workDir> so every session
 * the account creates lands in that directory. Other payloads pass through.
 */
function transformSessionCreate(body, user) {
  let doc;
  try {
    doc = JSON.parse(body.toString("utf8"));
  } catch {
    return body;
  }
  if (doc === null || typeof doc !== "object" || doc.payload === null || typeof doc.payload !== "object") return body;
  if (doc.payload.workspaceId === undefined) return body;
  const next = { ...doc, payload: { ...doc.payload, cwd: user.workDir.trim() } };
  delete next.payload.workspaceId;
  return Buffer.from(JSON.stringify(next), "utf8");
}

/**
 * HTTP reverse proxy for one authenticated request. When the account has a
 * workDir restriction and the request is a session.create, the body is
 * buffered and rewritten before being forwarded upstream.
 * @param getUser - optional (username) → {workDir} | undefined; enables the rewrite.
 * @param username - the authenticated account name.
 */
function proxyHttp(req, res, upstream, log, secure = false, getUser = undefined, username = "") {
  const noForwarding = NO_FORWARDING_PATHS.has(new URL(req.url ?? "/", "http://x").pathname);
  const headers = upstreamHeaders(req, upstream, secure, noForwarding);
  const transform = req.method === "POST" && String(req.url ?? "").startsWith("/api/session.create")
    && typeof getUser === "function"
    ? getUser(username)
    : undefined;
  const restricted = transform !== undefined && transform !== null
    && typeof transform.workDir === "string" && transform.workDir.trim() !== "";

  const begin = (body) => {
    const upstreamReq = httpRequest({
      host: upstream.host,
      port: upstream.port,
      method: req.method,
      path: req.url,
      headers: body !== null ? { ...headers, "content-length": body.length } : headers,
    }, (upstreamRes) => {
      const outHeaders = {};
      for (const [name, value] of Object.entries(upstreamRes.headers)) {
        if (value === undefined) continue;
        const lower = name.toLowerCase();
        if (HOP_BY_HOP.has(lower)) continue;
        outHeaders[lower] = value;
      }
      const contentType = String(upstreamRes.headers["content-type"] ?? "");
      const encodable = contentType.toLowerCase().includes("text/html")
        && upstreamRes.headers["content-encoding"] === undefined;
      if (!encodable || req.method === "HEAD") {
        res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.statusMessage, outHeaders);
        upstreamRes.pipe(res);
        return;
      }
      // Buffered HTML pass: inject the gateway trust marker, then forward.
      const chunks = [];
      let size = 0;
      let overflowed = false;
      upstreamRes.on("data", (chunk) => {
        if (overflowed) return;
        size += chunk.length;
        if (size > MAX_HTML_BUFFER_BYTES) {
          overflowed = true;
          upstreamRes.pause();
          res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.statusMessage, outHeaders);
          res.write(Buffer.concat(chunks));
          upstreamRes.pipe(res);
          upstreamRes.resume();
          return;
        }
        chunks.push(chunk);
      });
      upstreamRes.on("end", () => {
        if (overflowed || res.headersSent) return;
        const outBody = injectGatewayMarker(Buffer.concat(chunks));
        const { "content-length": _dropped, ...headersWithoutLength } = outHeaders;
        res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.statusMessage, headersWithoutLength);
        res.end(outBody);
      });
      upstreamRes.on("error", (err) => {
        log?.(`upstream html stream failed: ${err instanceof Error ? err.message : String(err)}`);
        if (!res.headersSent) res.destroy();
      });
    });
    upstreamReq.on("error", (err) => {
      log?.(`upstream request failed: ${err instanceof Error ? err.message : String(err)}`);
      if (!res.headersSent) {
        res.writeHead(502, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
        res.end("bad gateway: the harness web server is unreachable");
      } else res.destroy();
    });
    req.on("error", () => upstreamReq.destroy());
    res.on("close", () => upstreamReq.destroy());
    if (body !== null) upstreamReq.end(body);
    else req.pipe(upstreamReq);
  };

  if (!restricted) return begin(null);
  readBody(req).then((body) => {
    begin(transformSessionCreate(body, transform));
  }).catch(() => {
    if (!res.headersSent) sendJson(res, 400, { error: "body too large" });
  });
}

/**
 * Serve the gateway's configuration files as plain text for browser viewing
 * (the harness "打开配置文件" opens natively, which cannot work on a headless
 * server). Every file is read fresh; missing files render a note.
 */
function serveConfig(req, res, log, configFiles) {
  const download = new URL(req.url ?? "/", "http://x").searchParams.get("download") === "1";
  let body = "";
  for (const file of configFiles) {
    body += "########## " + file.path + " ##########\n";
    try {
      body += readFileSync(file.path, "utf8");
    } catch (err) {
      body += "（无法读取：" + (err instanceof Error ? err.message : String(err)) + "）\n";
    }
    body += "\n\n";
  }
  if (configFiles.length === 0) body = "（未配置配置文件）\n";
  res.writeHead(200, {
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store",
    ...(download ? { "content-disposition": "attachment; filename=\"dsh-gateway-config.txt\"" } : {}),
  });
  res.end(body);
}

/** Serve the credentials YAML as plain text (the config editor's load). */
function serveCredentials(res, log, credentialsFile) {
  let text;
  try {
    text = readFileSync(credentialsFile, "utf8");
  } catch (err) {
    log?.(`web-auth: credentials read failed: ${err instanceof Error ? err.message : String(err)}`);
    return sendJson(res, 500, { error: "cannot read credentials file" });
  }
  res.writeHead(200, {
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store",
    ...SECURITY_HEADERS,
  });
  res.end(text);
}

/** Save the credentials YAML from the config editor (validated, atomic). */
async function saveCredentials(req, res, log, credentialsFile) {
  let body;
  try {
    body = await readBody(req);
  } catch {
    return sendJson(res, 400, { error: "body too large" });
  }
  const { error } = saveCredentialsText(credentialsFile, body.toString("utf8"));
  if (error !== undefined) {
    log?.(`web-auth: config save rejected: ${error}`);
    return sendJson(res, 400, { error });
  }
  log?.(`web-auth: credentials file saved (${Buffer.byteLength(body)} bytes)`);
  return sendJson(res, 200, { ok: true });
}

/** Write a raw HTTP request line for an upstream WebSocket handshake. */
function rawUpgradeRequest(req, upstream, head, secure = false) {
  const authority = `${upstream.host}:${String(upstream.port)}`;
  const lines = [`${req.method} ${req.url} HTTP/1.1`];
  // The handshake NEEDS its Connection/Upgrade headers — only the other
  // hop-by-hop headers are stripped.
  const strip = new Set([...HOP_BY_HOP].filter((name) => name !== "connection" && name !== "upgrade"));
  const raw = req.rawHeaders ?? [];
  for (let i = 0; i < raw.length; i += 2) {
    const name = raw[i];
    const value = raw[i + 1];
    const lower = name.toLowerCase();
    if (strip.has(lower)) continue;
    if (lower === "origin" || lower === "x-forwarded-for" || lower === "x-forwarded-proto" || lower === "x-forwarded-host") continue;
    lines.push(`${name}: ${value}`);
  }
  lines.push(`Host: ${authority}`);
  if (req.headers.origin !== undefined) lines.push(`Origin: http://${authority}`);
  const clientIp = req.socket.remoteAddress ?? "";
  lines.push(`X-Forwarded-For: ${clientIp}`);
  lines.push(`X-Forwarded-Proto: ${secure ? "https" : "http"}`);
  lines.push(`X-Forwarded-Host: ${String(req.headers.host ?? authority)}`);
  lines.push("", "");
  const headBuf = Buffer.from(lines.join("\r\n"), "latin1");
  return head.length > 0 ? Buffer.concat([headBuf, head]) : headBuf;
}

/** WebSocket reverse proxy for one authenticated upgrade. */
function proxyUpgrade(req, socket, head, upstream, log, secure = false) {
  const upstreamSocket = netConnect(upstream.port, upstream.host, () => {
    upstreamSocket.write(rawUpgradeRequest(req, upstream, head, secure));
    socket.pipe(upstreamSocket);
    upstreamSocket.pipe(socket);
  });
  upstreamSocket.on("error", (err) => {
    log?.(`upstream websocket failed: ${err instanceof Error ? err.message : String(err)}`);
    socket.destroy();
  });
  socket.on("error", () => upstreamSocket.destroy());
  socket.on("close", () => upstreamSocket.destroy());
  upstreamSocket.on("close", () => socket.destroy());
}

function rejectUpgrade(socket, status, text) {
  const body = String(text ?? "");
  socket.end([
    `HTTP/1.1 ${status}`,
    "Connection: close",
    "Content-Type: text/plain; charset=utf-8",
    `Content-Length: ${Buffer.byteLength(body)}`,
    "",
    body,
  ].join("\r\n"));
}

/**
 * Create the gateway server(s).
 * @param options - logger, getUpstream (→ {host,port} | null), credentialsFile,
 *   sessionStore, throttle, cookie settings, logAccess, tls ({cert, key} to
 *   also serve HTTPS).
 * @returns { listen, close, server }
 */
export function createGateway(options) {
  const {
    logger = console,
    getUpstream,
    credentialsFile,
    sessionStore,
    throttle,
    cookieName = "dsh_session",
    sessionTtlHours = 24,
    cookieSecure = false,
    cookiePersistent = false,
    logAccess = true,
    tls = undefined,
    httpEnabled = true,
    configFiles = [],
    getUser = undefined,
    trustedDomains = ["*"],
    host = "0.0.0.0",
    httpsPort = 8443,
  } = options;

  // Live gateway-settings state (the gear-menu form reads/writes these).
  let settingsState = {
    httpsPort: Number.isInteger(httpsPort) ? httpsPort : 8443,
    trustedDomains: Array.isArray(trustedDomains) ? trustedDomains.map(String) : ["*"],
  };
  let boundHttpsPort = settingsState.httpsPort;

  // Live trusted-domain predicate; setTrustedDomains() recompiles it.
  let trustedHost = compileTrustedDomains(settingsState.trustedDomains);

  /** Rebind the trusted-domain fence from a rule list (settings edits). */
  const setTrustedDomains = (rules) => {
    settingsState.trustedDomains = Array.isArray(rules) ? rules.map(String) : ["*"];
    trustedHost = compileTrustedDomains(settingsState.trustedDomains);
  };

  const log = (...args) => { try { logger.info?.(...args) ?? logger.log?.(...args); } catch { /* logging must never kill the gateway */ } };

  /**
   * Trusted-domain fence for one request. The Host header is the primary
   * gate (DNS-rebinding defense — it cannot be forged by a rebound page).
   * An Origin header is compared ONLY when it is a concrete, parseable
   * origin: opaque origins ("null", sandboxed iframes/previews) and missing
   * Origins carry no evidence and are never rejected on their own.
   * @returns {ok: true} or {ok: false, reason}.
   */
  const fenceAllowed = (req) => {
    const hostHeader = String(req.headers.host ?? "");
    if (!trustedHost(hostHeader)) return { ok: false, reason: `untrusted host: ${hostHeader}` };
    const originHeader = req.headers.origin;
    if (typeof originHeader === "string" && originHeader !== "" && originHeader !== "null") {
      let originHost = null;
      try {
        originHost = new URL(originHeader).host;
      } catch {
        originHost = null; // not a browser origin; no evidence to compare
      }
      if (originHost !== null && !trustedHost(originHost)) return { ok: false, reason: "untrusted origin" };
    }
    return { ok: true };
  };

  const buildCookie = (token) => [
    `${cookieName}=${token}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    ...(cookieSecure ? ["Secure"] : []),
    ...(cookiePersistent ? [`Max-Age=${Math.floor(sessionTtlHours * 3600)}`] : []),
  ].join("; ");

  const authenticated = (req) => sessionStore.get(parseCookies(req).get(cookieName));

  const clientKey = (req) => String(req.socket.remoteAddress ?? "unknown");

  const serveLogin = (req, res, status, error) => {
    sendHtml(res, status, loginPageHtml({ error, sessionHours: sessionTtlHours }));
  };

  const handleLogin = async (req, res) => {
    const key = clientKey(req);
    const blocked = throttle.blockedFor(key);
    if (blocked > 0) {
      log(`web-auth: login blocked for ${key} (${blocked}s remaining)`);
      return serveLogin(req, res, 429, "locked");
    }
    let credentials;
    try {
      credentials = await parseCredentials(req);
    } catch {
      return serveLogin(req, res, 400, "malformed");
    }
    if (credentials.username === "" || credentials.password === "") {
      throttle.fail(key);
      return serveLogin(req, res, 401, "required");
    }
    const { users, error } = loadUsers(credentialsFile);
    if (error !== undefined) {
      log(`web-auth: ${error}`);
      return sendJson(res, 503, { error: "credentials unavailable" });
    }
    if (!verifyUser(users, credentials.username, credentials.password)) {
      throttle.fail(key);
      log(`web-auth: login failed for "${credentials.username}" from ${key}`);
      return serveLogin(req, res, 401, "invalid");
    }
    throttle.success(key);
    const token = sessionStore.create(credentials.username);
    log(`web-auth: login ok for "${credentials.username}" from ${key}`);
    res.writeHead(303, {
      location: safeNext(credentials.next),
      "set-cookie": buildCookie(token),
      "cache-control": "no-store",
    });
    res.end();
  };

  /** The gear-menu form state: primary account + gateway settings (no secrets). */
  const serveSettings = (res) => {
    const primary = loadPrimarySettings(credentialsFile);
    return sendJson(res, 200, {
      ok: true,
      value: {
        username: primary.username,
        httpsPort: settingsState.httpsPort,
        trustedDomains: settingsState.trustedDomains,
      },
    });
  };

  /** Save the gear-menu form: account rename/password + port + trusted domains. */
  const saveSettings = async (req, res) => {
    let body;
    try {
      body = await readBody(req);
    } catch {
      return sendJson(res, 400, { error: "body too large" });
    }
    let parsed;
    try {
      parsed = JSON.parse(body.toString("utf8"));
    } catch {
      return sendJson(res, 400, { error: "request body must be JSON" });
    }
    const result = applyGatewaySettings(credentialsFile, {
      username: parsed?.username,
      password: parsed?.password,
      httpsPort: parsed?.httpsPort,
      trustedDomains: parsed?.trustedDomains,
    });
    if (result.error !== undefined) {
      log?.(`web-auth: settings save rejected: ${result.error}`);
      return sendJson(res, 400, { error: result.error });
    }
    setTrustedDomains(result.value.trustedDomains);
    settingsState.httpsPort = result.value.httpsPort;
    if (result.value.httpsPort !== boundHttpsPort) {
      boundHttpsPort = result.value.httpsPort;
      try {
        const bound = await setHttpsPort(host, result.value.httpsPort);
        log?.(`web-auth: HTTPS 监听端口已切换为 ${String(bound)}`);
      } catch (err) {
        boundHttpsPort = null;
        log?.(`web-auth: HTTPS 端口切换失败：${err instanceof Error ? err.message : String(err)}`);
      }
    }
    log?.(`web-auth: settings saved (account ${result.value.username}, port ${result.value.httpsPort})`);
    return sendJson(res, 200, { ok: true, value: result.value });
  };

  const handle = async (req, res, secure) => {
    const url = new URL(req.url ?? "/", "http://x");
    const path = url.pathname;

    // Trusted-domain fence (checked before anything else, even /login): the
    // Host header must be allowed, and a concrete Origin header — when
    // present — must be allowed too. Opaque ("null") and missing Origins are
    // never rejected on their own (sandboxed iframes/previews). Defaults to
    // "*" (any domain). A restricted list blocks DNS-rebinding and
    // unintended hostname exposure.
    const fence = fenceAllowed(req);
    if (!fence.ok) {
      log(`web-auth: rejected ${fence.reason}`);
      return sendJson(res, 403, { error: fence.reason });
    }

    if (path === "/login" || path === "/login/") {
      if (req.method === "GET" || req.method === "HEAD") return serveLogin(req, res, 200, null);
      if (req.method === "POST") return handleLogin(req, res);
      res.writeHead(405, { allow: "GET, POST", ...SECURITY_HEADERS });
      return res.end();
    }
    if (path === "/logout" || path === "/logout/") {
      const session = authenticated(req);
      if (session !== null) {
        sessionStore.delete(parseCookies(req).get(cookieName));
        log(`web-auth: logout for "${session.username}"`);
      }
      return redirect(res, "/login");
    }

    // Public metadata (PWA manifest, favicon, robots): serve without a session.
    if (PUBLIC_PATHS.has(path)) {
      const upstream = getUpstream();
      if (upstream === null) {
        return sendJson(res, 503, { error: "harness web server not ready" });
      }
      proxyHttp(req, res, upstream, (message) => log(`web-auth: ${message}`), secure);
      return;
    }

    const session = authenticated(req);
    if (session === null) {
      const accept = String(req.headers.accept ?? "");
      if (req.method === "GET" && accept.includes("text/html")) {
        const next = url.pathname + url.search;
        return redirect(res, `/login?next=${encodeURIComponent(next)}`);
      }
      return sendJson(res, 401, { error: "login required" });
    }

    if (req.method === "GET" && path === "/dsh-gateway/config") {
      return serveConfig(req, res, log, configFiles);
    }

    if (path === "/dsh-gateway/config/credentials") {
      if (req.method === "GET") return serveCredentials(res, log, credentialsFile);
      if (req.method === "PUT") return saveCredentials(req, res, log, credentialsFile);
      res.writeHead(405, { allow: "GET, PUT", ...SECURITY_HEADERS });
      return res.end();
    }

    if (path === "/dsh-gateway/config/settings") {
      if (req.method === "GET") return serveSettings(res);
      if (req.method === "PUT") return saveSettings(req, res);
      res.writeHead(405, { allow: "GET, PUT", ...SECURITY_HEADERS });
      return res.end();
    }

    if (logAccess) log(`web-auth: ${session.username} ${req.method} ${url.pathname}`);
    const upstream = getUpstream();
    if (upstream === null) {
      return sendJson(res, 503, { error: "harness web server not ready" });
    }
    proxyHttp(req, res, upstream, (message) => log(`web-auth: ${message}`), secure, getUser, session.username);
  };

  const wireUpgrade = (server, secure) => {
    server.on("upgrade", (req, socket, head) => {
      const fence = fenceAllowed(req);
      if (!fence.ok) {
        rejectUpgrade(socket, 403, fence.reason);
        return;
      }
      if (authenticated(req) === null) {
        rejectUpgrade(socket, 401, "login required");
        return;
      }
      const upstream = getUpstream();
      if (upstream === null) {
        rejectUpgrade(socket, 503, "harness web server not ready");
        return;
      }
      proxyUpgrade(req, socket, head, upstream, (message) => log(`web-auth: ${message}`), secure);
    });
  };

  const wireClientError = (server) => {
    server.on("clientError", (err, socket) => {
      if (err?.code === "HPE_HEADER_OVERFLOW") {
        socket.end("HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n");
        return;
      }
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    });
  };

  const requestListener = (secure) => (req, res) => {
    handle(req, res, secure).catch((err) => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      log(`web-auth: request error: ${err instanceof Error ? err.message : String(err)}`);
      sendJson(res, 500, { error: "gateway error" });
    });
  };

  const buildHttp = () => {
    const srv = createServer(requestListener(false));
    wireUpgrade(srv, false);
    wireClientError(srv);
    return srv;
  };
  const buildHttps = () => {
    const srv = createHttpsServer(tls, requestListener(true));
    wireUpgrade(srv, true);
    wireClientError(srv);
    return srv;
  };

  const state = {
    server: httpEnabled ? buildHttp() : null,
    httpsServer: tls !== undefined && tls !== null ? buildHttps() : null,
  };
  if (state.server === null && state.httpsServer === null) {
    throw new Error("web-auth: neither HTTP nor HTTPS listening is enabled");
  }

  const listenOne = (srv, host, port) => new Promise((resolve, reject) => {
    srv.once("error", reject);
    srv.listen(port, host, () => {
      srv.off("error", reject);
      srv.on("error", (err) => log(`web-auth: server error: ${err.message}`));
      resolve(srv.address().port);
    });
  });

  const closeOne = (srv) => new Promise((done) => {
    srv.closeAllConnections?.();
    srv.close(() => done());
  });

  const listen = (host, port, httpsPort) => Promise.all([
    state.server !== null ? listenOne(state.server, host, port) : Promise.resolve(null),
    state.httpsServer !== null ? listenOne(state.httpsServer, host, httpsPort) : Promise.resolve(null),
  ]).then(([httpPort, tlsPort]) => ({ host, port: httpPort, httpsPort: tlsPort }));

  /** Rebind the HTTPS listener on a new port (settings-page port change). */
  const setHttpsPort = async (host, port) => {
    if (tls === undefined || tls === null) throw new Error("web-auth: TLS is not enabled, cannot rebind the HTTPS listener");
    const next = buildHttps();
    const bound = await listenOne(next, host, port);
    const previous = state.httpsServer;
    state.httpsServer = next;
    if (previous !== null) await closeOne(previous);
    return bound;
  };

  const close = () => Promise.all([
    state.server !== null ? closeOne(state.server) : Promise.resolve(),
    state.httpsServer !== null ? closeOne(state.httpsServer) : Promise.resolve(),
  ]).then(() => void 0);

  return { listen, close, setHttpsPort, setTrustedDomains, get server() { return state.server; }, get httpsServer() { return state.httpsServer; } };
}
