// dsh-web-auth-gateway — Cordis plugin that mounts the remote-login gateway
// beside the harness web server.
//
// The harness webServer stays loopback-bound (the harness refuses 0.0.0.0 for
// safety: it would expose remote code execution). This plugin is the
// authentication layer that makes remote access safe: it binds its OWN
// server to 0.0.0.0, requires a username/password login for every browser
// session, caps sessions at `sessionTtlHours` (default 24), and reverse-
// proxies authenticated traffic to the internal web server.
//
// The plugin deliberately has ZERO footprint in the harness's official
// settings system: no settings namespace is registered, nothing is written
// to the harness settings store, and the client half does not depend on the
// settings UI. All configuration (account, HTTPS port, trusted domains)
// lives in the plugin's own credentials YAML (a `gateway:` section plus the
// `users:` list) and is edited through the gateway's own endpoints
// (/dsh-gateway/config/settings, /dsh-gateway/config/credentials) from the
// plugin's gear menu.
import z from "@deepseek-ai/schemastery";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { createGateway } from "./gateway.js";
import { generatePassword, loadPrimarySettings, loadUsers, LoginThrottle, SessionStore, writeUsersFile } from "./auth.js";

export const name = "dsh-web-auth-gateway";

// webServer (upstream port) must exist.
export const inject = ["webServer"];

export const Config = z.object({
  /** Bind host of the login gateway. 0.0.0.0 exposes it on all interfaces. */
  host: z.string().default("0.0.0.0"),
  /** HTTP listen port (only used when httpEnabled is true; 0 = OS-assigned). */
  port: z.number().step(1).min(0).max(65535).default(8080),
  /** Serve the plain-HTTP listener. Off by default: HTTPS-only remote access. */
  httpEnabled: z.boolean().default(false),
  /** Credentials YAML file (username/password list). Empty → $DSH_HOME/web-auth.yaml. */
  credentialsFile: z.string().default(""),
  /** Server-side session validity in hours (default 24). */
  sessionTtlHours: z.number().step(1).min(1).max(24 * 30).default(24),
  /** Session cookie name. */
  cookieName: z.string().default("dsh_session"),
  /** Add the Secure cookie attribute (recommended with HTTPS-only). */
  cookieSecure: z.boolean().default(false),
  /** Persistent cookie (Max-Age) instead of a browser-session cookie. */
  cookiePersistent: z.boolean().default(false),
  /** Upstream harness web server host (loopback). */
  upstreamHost: z.string().default("127.0.0.1"),
  /**
   * Trusted request domains (Host/Origin allowlist): "*" = any domain
   * (default); otherwise only matching hosts are served, which blocks
   * DNS-rebinding and unintended hostname exposure. Rules support exact
   * hosts, "host:port", and "*.suffix" wildcards. The value in the
   * credentials file's `gateway:` section overrides this fallback.
   */
  trustedDomains: z.array(z.string()).default(["*"]),
  /** Failed-login throttle: attempts before lockout. */
  maxLoginAttempts: z.number().step(1).min(1).default(5),
  /** Failed-login throttle: sliding window in seconds. */
  loginWindowSeconds: z.number().step(1).min(10).default(600),
  /** Failed-login throttle: lockout duration in seconds. */
  lockoutSeconds: z.number().step(1).min(10).default(600),
  /** Log proxied requests through ctx.logger. */
  logAccess: z.boolean().default(true),
  /** Serve HTTPS (required for remote access; browsers only expose WebCrypto in secure contexts). */
  httpsEnabled: z.boolean().default(false),
  /** HTTPS listen port (0 = OS-assigned). The credentials file's gateway: section overrides this. */
  httpsPort: z.number().step(1).min(0).max(65535).default(8443),
  /** TLS certificate file. Empty → $DSH_HOME/web-auth-cert.pem. */
  httpsCertFile: z.string().default(""),
  /** TLS private key file. Empty → $DSH_HOME/web-auth-key.pem. */
  httpsKeyFile: z.string().default(""),
});

/** Default credentials file location: $DSH_HOME/web-auth.yaml (or ~/.dsh). */
export function defaultCredentialsFile() {
  const home = process.env.DSH_HOME?.trim();
  return path.join(home !== undefined && home !== "" ? home : path.join(homedir(), ".dsh"), "web-auth.yaml");
}

/** Default TLS certificate/key locations under the harness home. */
export function defaultTlsFiles() {
  const home = process.env.DSH_HOME?.trim();
  const base = home !== undefined && home !== "" ? home : path.join(homedir(), ".dsh");
  return { certFile: path.join(base, "web-auth-cert.pem"), keyFile: path.join(base, "web-auth-key.pem") };
}

export async function apply(ctx, config) {
  const credentialsFile = config.credentialsFile.trim() !== "" ? config.credentialsFile : defaultCredentialsFile();

  // First use: no credentials file yet — create the default account and print
  // the credentials to the console exactly once.
  let firstUse = false;
  try {
    readFileSync(credentialsFile);
  } catch {
    firstUse = true;
  }
  if (firstUse) {
    writeUsersFile(credentialsFile, [{ username: "admin", password: generatePassword() }]);
  }

  const sessions = new SessionStore(config.sessionTtlHours * 3600 * 1000);
  const throttle = new LoginThrottle({
    maxAttempts: config.maxLoginAttempts,
    windowSeconds: config.loginWindowSeconds,
    lockoutSeconds: config.lockoutSeconds,
  });

  // Effective gateway settings: the credentials file's gateway: section wins
  // over the config fallbacks (the gear menu edits that section live).
  const primary = loadPrimarySettings(credentialsFile);
  const initialHttpsPort = primary.httpsPort ?? config.httpsPort;
  const initialTrustedDomains = primary.trustedDomains ?? config.trustedDomains;

  // ── TLS ────────────────────────────────────────────────────────────────────
  let tls = undefined;
  if (config.httpsEnabled) {
    const defaults = defaultTlsFiles();
    const certFile = config.httpsCertFile.trim() !== "" ? config.httpsCertFile : defaults.certFile;
    const keyFile = config.httpsKeyFile.trim() !== "" ? config.httpsKeyFile : defaults.keyFile;
    let cert, key;
    try {
      cert = readFileSync(certFile);
      key = readFileSync(keyFile);
    } catch (err) {
      throw new Error(`web-auth: httpsEnabled but TLS files unreadable (${certFile} / ${keyFile}): ${err instanceof Error ? err.message : String(err)} — generate them with "dsh-web-auth gen-cert"`);
    }
    tls = { cert, key };
  }

  // ── gateway ────────────────────────────────────────────────────────────────
  const consoleLogger = {
    info: (...args) => console.log("[web-auth]", ...args),
    warn: (...args) => console.warn("[web-auth]", ...args),
  };
  const gateway = createGateway({
    logger: consoleLogger,
    configFiles: [{ path: credentialsFile }],
    credentialsFile,
    sessionStore: sessions,
    throttle,
    cookieName: config.cookieName,
    sessionTtlHours: config.sessionTtlHours,
    cookieSecure: config.cookieSecure,
    cookiePersistent: config.cookiePersistent,
    logAccess: config.logAccess,
    tls,
    httpEnabled: config.httpEnabled,
    host: config.host,
    httpsPort: initialHttpsPort,
    trustedDomains: initialTrustedDomains,
    // WorkDir restrictions are read fresh from the credentials file on every
    // session.create, so config-editor changes apply immediately (no restart).
    getUser: (username) => {
      const { users } = loadUsers(credentialsFile);
      const entry = users.find((u) => u !== null && typeof u === "object" && String(u.username ?? "") === username);
      if (entry === undefined) return undefined;
      return {
        username: String(entry.username),
        workDir: typeof entry.workDir === "string" ? entry.workDir : "",
      };
    },
    getUpstream: () => {
      const port = ctx.get("webServer")?.port;
      if (port === undefined || port === null) return null;
      return { host: config.upstreamHost, port };
    },
  });

  ctx.effect(() => async () => {
    sessions.close();
    throttle.close();
    await gateway.close();
  }, "dsh-web-auth-gateway.close");

  // First use: print the credentials that are actually effective.
  if (firstUse) {
    const firstAccount = loadUsers(credentialsFile).users[0];
    console.log("==================================================");
    console.log("[web-auth] 首次使用：默认登录账号已就绪（请登录后尽快在 ⚙ 菜单修改密码）");
    console.log(`[web-auth]   用户名: ${firstAccount?.username ?? "admin"}`);
    console.log(`[web-auth]   密码:   ${firstAccount?.password ?? ""}`);
    console.log("==================================================");
  }

  // Bind with retry: during a live row swap the previous plugin's listener may
  // still be closing, so an EADDRINUSE at this instant must retry, not fail.
  let addr = null;
  let lastError = null;
  for (let attempt = 0; attempt < 5 && addr === null; attempt++) {
    try {
      addr = await gateway.listen(config.host, config.port, initialHttpsPort);
    } catch (err) {
      lastError = err;
      if (err?.code !== "EADDRINUSE") throw err;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
  if (addr === null) throw lastError;
  const hostLabel = config.host === "0.0.0.0" ? "<this-host>" : config.host;
  const parts = [];
  if (addr.port !== null) parts.push(`http://${hostLabel}:${String(addr.port)}`);
  if (addr.httpsPort !== null) parts.push(`https://${hostLabel}:${String(addr.httpsPort)} (self-signed)`);
  console.log(`[web-auth] 登录网关已启动：${parts.join(" + ")}`);
  console.log(`[web-auth] 凭据文件：${credentialsFile}（账号：${primary.username === "" ? "admin" : primary.username}，会话有效期 ${String(config.sessionTtlHours)} 小时，信任域：${initialTrustedDomains.join(", ")}）`);
}
