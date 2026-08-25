// Standalone smoke test for dsh-remote-gateway (no harness needed):
// exercises the gateway against a fake upstream HTTP/WebSocket server.
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { connect as netConnect } from "node:net";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import https from "node:https";
import { WebSocket, WebSocketServer } from "ws";
import { createGateway, compileTrustedDomains, hostMatchesTrusted, parseTrustedDomainsList } from "../lib/gateway.js";
import { SessionStore, LoginThrottle, loadUsers, verifyUser, validateUsersList } from "../lib/auth.js";
import { generateSelfSignedCert } from "../lib/cert.js";

let passed = 0;
const ok = (name) => { passed++; console.log(`  ✓ ${name}`); };

// ── 1. credentials verification ─────────────────────────────────────────────
{
  const dir = mkdtempSync(path.join(tmpdir(), "dsh-auth-"));
  const file = path.join(dir, "creds.yaml");
  writeFileSync(file, [
    "users:",
    "  - username: admin",
    "    password: s3cret",
    "  - username: hashed",
    `    passwordHash: "sha256:${createHash("sha256").update("hunter2").digest("hex")}"`,
    "",
  ].join("\n"));
  const { users, error } = loadUsers(file);
  assert.equal(error, undefined);
  assert.equal(users.length, 2);
  assert.equal(verifyUser(users, "admin", "s3cret"), true);
  assert.equal(verifyUser(users, "admin", "wrong"), false);
  assert.equal(verifyUser(users, "admin", ""), false);
  assert.equal(verifyUser(users, "hashed", "hunter2"), true);
  assert.equal(verifyUser(users, "hashed", "s3cret"), false);
  assert.equal(verifyUser(users, "ghost", "s3cret"), false);
  assert.deepEqual(loadUsers(path.join(dir, "missing.yaml")).error !== undefined, true);
  ok("credentials loading and verification (plain + sha256 hash)");

  // account-list validation (settings page invariants)
  validateUsersList([{ username: "admin" }, { username: "bob" }]);
  assert.throws(() => validateUsersList([{ username: "bob" }]), /admin/);
  assert.throws(() => validateUsersList([{ username: "admin" }, { username: "admin" }]), /duplicate/);
  assert.throws(() => validateUsersList([{ username: "" }]), /non-empty/);
  ok("account list validation (admin required, unique, non-empty)");
}

// ── 1b. CLI account editing (set-user; add-user/remove-user removed) ────────
{
  const cli = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "lib", "cli.js");
  const dir = mkdtempSync(path.join(tmpdir(), "dsh-cli-"));
  const run = (args) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", env: { ...process.env, DSH_HOME: dir } });
  const credsFile = path.join(dir, "web-auth.yaml");

  let r = run(["init", "--username", "admin", "--password", "pw1"]);
  assert.equal(r.status, 0, r.stderr);
  let doc = loadUsers(credsFile);
  assert.equal(verifyUser(doc.users, "admin", "pw1"), true);

  // set-user: password-only change
  r = run(["set-user", "--password", "pw2"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /admin/);
  doc = loadUsers(credsFile);
  assert.equal(verifyUser(doc.users, "admin", "pw1"), false);
  assert.equal(verifyUser(doc.users, "admin", "pw2"), true);
  ok("CLI set-user changes the current account's password");

  // set-user: rename + password + workDir in one call
  r = run(["set-user", "--username", "root", "--password", "pw3", "--work-dir", "/srv/x"]);
  assert.equal(r.status, 0, r.stderr);
  doc = loadUsers(credsFile);
  assert.equal(verifyUser(doc.users, "root", "pw3"), true);
  assert.equal(verifyUser(doc.users, "admin", "pw2"), false);
  assert.equal(doc.users[0].workDir, "/srv/x");
  ok("CLI set-user renames the current account and sets workDir");

  // set-user: --password-hash wins and drops the stale plaintext
  const hex = createHash("sha256").update("hunter2").digest("hex");
  r = run(["set-user", "--password", "ignored", "--password-hash", `sha256:${hex}`]);
  assert.equal(r.status, 0, r.stderr);
  doc = loadUsers(credsFile);
  assert.equal(verifyUser(doc.users, "root", "hunter2"), true);
  assert.equal(verifyUser(doc.users, "root", "ignored"), false);
  assert.equal(doc.users[0].passwordHash, `sha256:${hex}`);
  assert.equal(doc.users[0].password, undefined);
  ok("CLI set-user accepts a sha256 hash (plaintext dropped)");

  // invalid hash format → rejected before any write
  r = run(["set-user", "--password-hash", "nope"]);
  assert.equal(r.status, 1);
  doc = loadUsers(credsFile);
  assert.equal(verifyUser(doc.users, "root", "hunter2"), true);
  // nothing to change → rejected
  r = run(["set-user"]);
  assert.equal(r.status, 1);
  // add-user / remove-user are gone: unknown command → usage, exit 2
  for (const cmd of ["add-user", "remove-user"]) {
    r = run([cmd, "--username", "bob", "--password", "x"]);
    assert.equal(r.status, 2, `${cmd} must no longer exist`);
  }
  ok("CLI rejects bad hash / empty set-user; add-user & remove-user removed");
}

// ── 2. session store TTL ────────────────────────────────────────────────────
{
  const store = new SessionStore(50); // 50 ms
  const token = store.create("admin");
  assert.equal(store.get(token).username, "admin");
  assert.equal(store.get("nope"), null);
  await new Promise((r) => setTimeout(r, 70));
  assert.equal(store.get(token), null);
  store.close();
  ok("session tokens expire after TTL");
}

// ── 3. login throttle ───────────────────────────────────────────────────────
{
  const throttle = new LoginThrottle({ maxAttempts: 3, windowSeconds: 600, lockoutSeconds: 600 });
  throttle.fail("ip1"); throttle.fail("ip1");
  assert.equal(throttle.blockedFor("ip1"), 0);
  throttle.fail("ip1");
  assert.ok(throttle.blockedFor("ip1") > 0);
  assert.equal(throttle.blockedFor("ip2"), 0);
  throttle.success("ip1");
  assert.equal(throttle.blockedFor("ip1"), 0);
  throttle.close();
  ok("login throttle locks out after max failures");
}

// ── 3b. trusted-domain matcher ───────────────────────────────────────────────
{
  assert.equal(hostMatchesTrusted("myhost:8443", "*"), true);
  assert.equal(hostMatchesTrusted("anything.example", "*"), true);
  assert.equal(hostMatchesTrusted("myhost:8443", "myhost"), true);            // exact host, any port
  assert.equal(hostMatchesTrusted("myhost:8080", "myhost"), true);
  assert.equal(hostMatchesTrusted("other:8443", "myhost"), false);
  assert.equal(hostMatchesTrusted("myhost:8443", "myhost:8443"), true);       // exact host+port
  assert.equal(hostMatchesTrusted("myhost:8080", "myhost:8443"), false);
  assert.equal(hostMatchesTrusted("a.example.com:80", "*.example.com"), true); // suffix wildcard
  assert.equal(hostMatchesTrusted("example.com:80", "*.example.com"), false);  // bare apex not covered
  assert.equal(hostMatchesTrusted("evil-example.com", "*.example.com"), false);
  assert.equal(hostMatchesTrusted("MyHost", "myhost"), true);                 // case-insensitive
  assert.equal(hostMatchesTrusted("2001:db8::1", "2001:db8::1"), true);       // bare IPv6 passes whole
  assert.equal(hostMatchesTrusted("[::1]:8443", "::1"), true);                // bracketed IPv6 + port
  assert.equal(hostMatchesTrusted("[::1]", "::1"), true);
  assert.equal(hostMatchesTrusted("[::1]:8443", "[::1]:8443"), true);         // bracketed rule with port
  assert.equal(hostMatchesTrusted("[::1]:8443", "localhost"), false);         // hostname ≠ IPv6 literal
  const allow = compileTrustedDomains(["127.0.0.1", "trusted.test", "*.corp.test"]);
  assert.equal(allow("127.0.0.1:3000"), true);
  assert.equal(allow("trusted.test:8443"), true);
  assert.equal(allow("a.corp.test"), true);
  assert.equal(allow("evil.com"), false);
  assert.equal(compileTrustedDomains([])("127.0.0.1"), false);                // empty list denies all
  assert.deepEqual(parseTrustedDomainsList("a.com, *.b.com , c.com:8443"), ["a.com", "*.b.com", "c.com:8443"]);
  ok("trusted-domain rules match (wildcard/exact/port/suffix/IPv6)");
}

// ── 4. gateway flow against a fake upstream ─────────────────────────────────
{
  // Fake harness: serves an HTML page at /, an API at /api/ping that echoes
  // what it saw (host/origin/cookie), and a websocket echo at /ws.
  const seen = [];
  const sessionCreates = [];
  const upstream = createServer((req, res) => {
    if (req.url.startsWith("/api/ping")) {
      seen.push({ host: req.headers.host, origin: req.headers.origin, xfh: req.headers["x-forwarded-host"], xff: req.headers["x-forwarded-for"] });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    // Fake dshmarket process-control route: echoes the headers it saw, so the
    // test can assert the gateway forwards it WITHOUT any forwarding trace
    // (dshmarket's trustedRestartRequest rejects forwarded requests).
    if (req.url === "/dsh-market/restart" && req.method === "POST") {
      seen.push({ host: req.headers.host, origin: req.headers.origin, xfh: req.headers["x-forwarded-host"], xff: req.headers["x-forwarded-for"], forwarded: req.headers.forwarded, xri: req.headers["x-real-ip"] });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, restart: "scheduled" }));
      return;
    }
    if (req.url === "/api/session.create" && req.method === "POST") {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        sessionCreates.push(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ type: "server-response", rpcId: "x", result: { ok: true, value: { sessionId: "s1" } } }));
      });
      return;
    }
    // Fake vision-toolkit-like route: exact path + the same-origin fence the
    // toolkit applies (Origin must match Host). The gateway rewrites Origin to
    // the loopback authority, so the fence must pass for proxied requests.
    if (req.url.startsWith("/_dsh/vision-toolkit/settings")) {
      const origin = req.headers.origin;
      let sameOrigin = true;
      if (origin !== undefined) {
        try { sameOrigin = new URL(origin).host === req.headers.host; } catch { sameOrigin = false; }
      }
      if (!sameOrigin) {
        res.writeHead(403, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: { code: "origin-rejected" } }));
        return;
      }
      if (req.method === "GET") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, value: { hidden: false } }));
        return;
      }
      if (req.method === "POST") {
        const chunks = [];
        req.on("data", (c) => chunks.push(c));
        req.on("end", () => {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true, value: { echoed: JSON.parse(Buffer.concat(chunks).toString("utf8")) } }));
        });
        return;
      }
      res.writeHead(405, { allow: "GET, POST" });
      res.end();
      return;
    }
    res.writeHead(200, { "content-type": "text/html" });
    res.end("<!doctype html><title>harness</title>hello harness");
  });
  const wss = new WebSocketServer({ noServer: true });
  upstream.on("upgrade", (req, socket, head) => {
    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.on("message", (data) => ws.send(`echo:${data}`));
    });
  });
  await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const upstreamPort = upstream.address().port;

  const sessions = new SessionStore(24 * 3600 * 1000);
  const throttle = new LoginThrottle({ maxAttempts: 3, windowSeconds: 600, lockoutSeconds: 600 });
  const credsFile = path.join(mkdtempSync(path.join(tmpdir(), "dsh-auth-")), "creds.yaml");
  writeFileSync(credsFile, [
    "users:",
    "  - username: admin",
    "    password: gwpass",
    "  - username: restricted",
    "    password: rpass",
    "    workDir: /srv/restricted",
    "",
  ].join("\n"));
  const gateway = createGateway({
    logger: { info: () => {} },
    credentialsFile: credsFile,
    sessionStore: sessions,
    throttle,
    getUser: (username) => (username === "restricted" ? { username, workDir: "/srv/restricted" } : undefined),
    getUpstream: () => ({ host: "127.0.0.1", port: upstreamPort }),
  });
  const addr = await gateway.listen("127.0.0.1", 0);
  const base = `http://127.0.0.1:${addr.port}`;

  const get = (p, headers = {}) => fetch(`${base}${p}`, { headers: { accept: "text/html", ...headers }, redirect: "manual" });
  const post = (p, body, headers = {}) => fetch(`${base}${p}`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body, redirect: "manual",
  });

  // unauthenticated GET / → redirect to /login
  let res = await get("/");
  assert.equal(res.status, 303);
  assert.match(res.headers.get("location"), /^\/login\?next=/);
  ok("unauthenticated page request redirects to /login");

  // login page renders
  res = await get("/login");
  assert.equal(res.status, 200);
  const page = await res.text();
  assert.match(page, /用户名/);
  assert.match(page, /24 小时/);
  ok("login page renders (zh, 24h note)");

  // wrong credentials → 401 page with error
  res = await post("/login", "username=admin&password=wrong");
  assert.equal(res.status, 401);
  assert.match(await res.text(), /用户名或密码错误/);
  ok("wrong credentials rejected");

  // missing credentials → 401
  res = await post("/login", "username=&password=");
  assert.equal(res.status, 401);
  ok("empty credentials rejected");

  // correct credentials → 303 + session cookie
  res = await post("/login", "username=admin&password=gwpass&next=/app");
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "/app");
  const setCookie = res.headers.get("set-cookie");
  assert.match(setCookie, /dsh_session=[0-9a-f]{64}; Path=\/; HttpOnly; SameSite=Lax/);
  assert.doesNotMatch(setCookie, /Max-Age/); // browser-session cookie
  ok("login succeeds, issues HttpOnly session cookie, honors next");

  // unauthenticated API call → 401 JSON
  res = await fetch(`${base}/api/ping`, { headers: { accept: "application/json" } });
  assert.equal(res.status, 401);
  ok("unauthenticated API call → 401 JSON");

  // public metadata paths are served without a session (no 401 console noise)
  res = await fetch(`${base}/manifest.webmanifest`);
  assert.equal(res.status, 200);
  res = await fetch(`${base}/favicon.svg`);
  assert.equal(res.status, 200);
  ok("manifest/favicon public paths serve without login");

  // authenticated page request proxies through with loopbacked headers
  res = await fetch(`${base}/api/ping`, {
    headers: { cookie: "dsh_session=" + setCookie.match(/dsh_session=([0-9a-f]+)/)[1], origin: `http://192.168.1.50:${addr.port}` },
  });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
  assert.equal(seen[0].host, `127.0.0.1:${upstreamPort}`);
  assert.equal(seen[0].origin, `http://127.0.0.1:${upstreamPort}`);
  assert.equal(seen[0].xfh, `127.0.0.1:${addr.port}`);
  assert.ok(typeof seen[0].xff === "string" && seen[0].xff !== "", "x-forwarded-for present for ordinary API calls");
  ok("authenticated request proxied with Host/Origin loopbacked");

  // dshmarket process-control routes (restart/backup/self-uninstall) reject
  // ANY forwarding trace; the gateway must forward them WITHOUT
  // x-forwarded-for/forwarded/x-real-ip (Host/Origin still loopbacked).
  res = await fetch(`${base}/dsh-market/restart`, {
    method: "POST",
    headers: { cookie: "dsh_session=" + setCookie.match(/dsh_session=([0-9a-f]+)/)[1], origin: `https://192.168.1.50:${addr.port}` },
  });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, restart: "scheduled" });
  const restartSeen = seen[1];
  assert.equal(restartSeen.host, `127.0.0.1:${upstreamPort}`);
  assert.equal(restartSeen.origin, `http://127.0.0.1:${upstreamPort}`);
  assert.equal(restartSeen.xff, undefined, "no x-forwarded-for on process-control routes");
  assert.equal(restartSeen.forwarded, undefined);
  assert.equal(restartSeen.xri, undefined);
  assert.equal(restartSeen.xfh, `127.0.0.1:${addr.port}`);
  ok("process-control routes forwarded without forwarding trace (dshmarket restart guard passes)");

  // authenticated HTML request reaches the harness UI, with the gateway
  // trust marker injected (the client uses it to enable settings remotely)
  res = await get("/", { cookie: "dsh_session=" + setCookie.match(/dsh_session=([0-9a-f]+)/)[1] });
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /hello harness/);
  assert.match(html, /__DSH_AUTH_GATEWAY__/);
  ok("authenticated page request reaches upstream UI with gateway marker");

  // per-account workDir restriction: session.create is rewritten for a
  // restricted account (workspaceId replaced by cwd)
  res = await post("/login", "username=restricted&password=rpass");
  assert.equal(res.status, 303);
  const rToken = res.headers.get("set-cookie").match(/dsh_session=([0-9a-f]+)/)[1];
  res = await fetch(`${base}/api/session.create`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: `dsh_session=${rToken}` },
    body: JSON.stringify({ type: "client-request", rpcId: "sc1", method: "session.create", payload: { workspaceId: "w1" } }),
  });
  assert.equal(res.status, 200);
  assert.equal(sessionCreates.length, 1);
  assert.equal(sessionCreates[0].payload.cwd, "/srv/restricted");
  assert.equal(sessionCreates[0].payload.workspaceId, undefined);
  ok("session.create forced into the account workDir (workspaceId dropped)");

  // admin (no restriction) passes through untouched
  res = await post("/login", "username=admin&password=gwpass");
  const aToken = res.headers.get("set-cookie").match(/dsh_session=([0-9a-f]+)/)[1];
  res = await fetch(`${base}/api/session.create`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: `dsh_session=${aToken}` },
    body: JSON.stringify({ type: "client-request", rpcId: "sc2", method: "session.create", payload: { cwd: "/opt" } }),
  });
  assert.equal(res.status, 200);
  assert.equal(sessionCreates[1].payload.cwd, "/opt");
  ok("unrestricted account session.create passes through unchanged");

  // websocket without cookie → 401-ish rejection
  await new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${addr.port}/ws`);
    ws.on("error", () => {}); // expected: handshake refused
    ws.on("close", (code) => {
      assert.ok(code === 1006); // abnormal closure from refused upgrade
      resolve();
    });
  });
  ok("unauthenticated websocket rejected");

  // websocket with cookie → echo works through the proxy
  const token = setCookie.match(/dsh_session=([0-9a-f]+)/)[1];
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${addr.port}/ws`, { headers: { cookie: `dsh_session=${token}` } });
    ws.on("open", () => ws.send("ping"));
    ws.on("message", (data) => {
      assert.equal(data.toString(), "echo:ping");
      ws.close();
      resolve();
    });
    ws.on("error", reject);
  });
  ok("authenticated websocket proxied (echo)");

  // vision-toolkit-style routes proxy through the gateway with Origin
  // rewritten to the loopback authority, so the plugin's same-origin fence
  // (Origin must match Host) passes — this is the dsh-vision-toolkit
  // compatibility contract (its /_dsh/vision-toolkit/* handlers depend on it).
  res = await fetch(`${base}/_dsh/vision-toolkit/settings`, {
    headers: { cookie: `dsh_session=${token}`, origin: `http://192.168.1.50:${addr.port}` },
  });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, value: { hidden: false } });
  res = await fetch(`${base}/_dsh/vision-toolkit/settings`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: `dsh_session=${token}`,
      origin: `https://192.168.1.50:8443`,
    },
    body: JSON.stringify({ action: "health", testConnection: false }),
  });
  assert.equal(res.status, 200);
  const visionEcho = await res.json();
  assert.deepEqual(visionEcho.value.echoed, { action: "health", testConnection: false });
  ok("vision-toolkit-style routes proxy with loopbacked Origin (same-origin fence passes)");

  // ── trusted-domain fence (runtime-rebindable) ────────────────────────────
  // undici's fetch refuses to override the Host header, so Host-based cases
  // go through a raw socket (this is exactly how DNS-rebinding requests look:
  // the browser connects to the gateway IP but sends Host: attacker's domain).
  const rawRequest = (hostHeader, pathStr, extra = "") => new Promise((resolve, reject) => {
    const sock = netConnect(addr.port, "127.0.0.1", () => {
      sock.write(`GET ${pathStr} HTTP/1.1\r\nHost: ${hostHeader}\r\nConnection: close\r\n${extra}\r\n`);
    });
    let data = "";
    sock.on("data", (chunk) => { data += chunk.toString(); });
    sock.on("end", () => resolve(data));
    sock.on("error", reject);
  });
  // Default is "*" (wildcard), so everything above worked. Restrict now:
  // only 127.0.0.1 and trusted.test may reach the gateway.
  gateway.setTrustedDomains(["127.0.0.1", "trusted.test"]);
  // untrusted Host → 403 before anything else (even the login page)
  assert.match(await rawRequest("evil.com", "/login"), /403/);
  // trusted alternate host → still served (login page renders)
  assert.match(await rawRequest("trusted.test", "/login"), /200/);
  // valid Host but untrusted Origin → 403 (undici allows Origin overrides)
  res = await fetch(`${base}/api/ping`, {
    headers: { cookie: `dsh_session=${token}`, origin: "http://evil.com" },
  });
  assert.equal(res.status, 403);
  // opaque origin ("null", sandboxed iframes/previews) → NOT rejected: the
  // Host check is the gate, and opaque origins carry no origin evidence
  res = await fetch(`${base}/api/ping`, {
    headers: { cookie: `dsh_session=${token}`, origin: "null" },
  });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
  // malformed origin header → treated as no evidence, Host still gates
  res = await fetch(`${base}/api/ping`, {
    headers: { cookie: `dsh_session=${token}`, origin: "not-a-url" },
  });
  assert.equal(res.status, 200);
  // IPv6 bracketed Host passes when the rule is the bare IPv6 literal
  gateway.setTrustedDomains(["127.0.0.1", "::1"]);
  assert.match(await rawRequest("[::1]:8443", "/login"), /200/);
  // valid Host + valid Origin → proxied normally
  gateway.setTrustedDomains(["127.0.0.1", "trusted.test"]);
  res = await fetch(`${base}/api/ping`, {
    headers: { cookie: `dsh_session=${token}`, origin: "http://trusted.test" },
  });
  assert.equal(res.status, 200);
  // WebSocket upgrade with untrusted Host → rejected 403
  await new Promise((resolve) => {
    const sock = netConnect(addr.port, "127.0.0.1", () => {
      sock.write("GET /ws HTTP/1.1\r\nHost: evil.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dshprobe\r\nSec-WebSocket-Version: 13\r\n\r\n");
    });
    let got = "";
    sock.on("data", (chunk) => { got += chunk.toString(); });
    sock.on("end", () => { assert.match(got, /403/); resolve(); });
    sock.on("error", () => resolve());
  });
  // WebSocket upgrade with trusted Host but untrusted Origin → rejected too
  await new Promise((resolve) => {
    const sock = netConnect(addr.port, "127.0.0.1", () => {
      sock.write("GET /ws HTTP/1.1\r\nHost: trusted.test\r\nOrigin: http://evil.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dshprobe\r\nSec-WebSocket-Version: 13\r\n\r\n");
    });
    let got = "";
    sock.on("data", (chunk) => { got += chunk.toString(); });
    sock.on("end", () => { assert.match(got, /403/); resolve(); });
    sock.on("error", () => resolve());
  });
  // restore wildcard → everything passes again
  gateway.setTrustedDomains(["*"]);
  assert.match(await rawRequest("evil.com", "/login"), /200/);
  ok("trusted-domain fence rejects untrusted Host/Origin (HTTP + WS), rebinds live");

  // ── settings endpoint (the gear-menu form; no harness settings service) ──
  res = await fetch(`${base}/dsh-gateway/config/settings`, { headers: { cookie: `dsh_session=${token}` } });
  assert.equal(res.status, 200);
  let settings = await res.json();
  assert.equal(settings.value.username, "admin");
  assert.equal(settings.value.httpsPort, 8443);
  assert.deepEqual(settings.value.trustedDomains, ["*"]);
  ok("settings endpoint reports the primary account and gateway defaults");

  res = await fetch(`${base}/dsh-gateway/config/settings`);
  assert.equal(res.status, 401);
  ok("settings endpoint rejects unauthenticated access");

  // invalid trusted domains → 400, nothing written
  const settingsBefore = readFileSync(credsFile, "utf8");
  res = await fetch(`${base}/dsh-gateway/config/settings`, {
    method: "PUT",
    headers: { "content-type": "application/json", cookie: `dsh_session=${token}` },
    body: JSON.stringify({ username: "admin", password: "", httpsPort: 8443, trustedDomains: ["bad rule"] }),
  });
  assert.equal(res.status, 400);
  assert.equal(readFileSync(credsFile, "utf8"), settingsBefore);
  ok("settings endpoint rejects invalid trusted domains without writing");

  // valid save: password + HTTPS port + trusted domains, applied live
  res = await fetch(`${base}/dsh-gateway/config/settings`, {
    method: "PUT",
    headers: { "content-type": "application/json", cookie: `dsh_session=${token}` },
    body: JSON.stringify({ username: "admin", password: "setpass", httpsPort: 9443, trustedDomains: ["127.0.0.1"] }),
  });
  assert.equal(res.status, 200);
  settings = await res.json();
  assert.equal(settings.value.username, "admin");
  assert.equal(settings.value.httpsPort, 9443);
  assert.deepEqual(settings.value.trustedDomains, ["127.0.0.1"]);
  // persisted in the credentials file's gateway section
  assert.match(readFileSync(credsFile, "utf8"), /gateway:/);
  // the trusted-domain fence took effect live
  assert.match(await rawRequest("evil.com", "/login"), /403/);
  // the new password works for login
  res = await post("/login", "username=admin&password=setpass");
  assert.equal(res.status, 303);
  ok("settings endpoint saves account + port + trusted domains and applies live");

  // restore wildcard trust + original port for the rest of the suite
  res = await fetch(`${base}/dsh-gateway/config/settings`, {
    method: "PUT",
    headers: { "content-type": "application/json", cookie: `dsh_session=${token}` },
    body: JSON.stringify({ username: "admin", password: "", httpsPort: 8443, trustedDomains: ["*"] }),
  });
  assert.equal(res.status, 200);
  assert.match(await rawRequest("evil.com", "/login"), /200/);
  ok("settings endpoint restores wildcard trust");

  // config editor: the credentials file is served as text to authenticated clients
  res = await fetch(`${base}/dsh-gateway/config/credentials`, { headers: { cookie: `dsh_session=${token}` } });
  assert.equal(res.status, 200);
  assert.match(await res.text(), /username: admin/);
  ok("config editor loads the credentials file (authenticated)");

  // config editor: unauthenticated access is refused
  res = await fetch(`${base}/dsh-gateway/config/credentials`);
  assert.equal(res.status, 401);
  ok("config editor rejects unauthenticated access");

  // invalid YAML → 400 and the file stays untouched
  const credsBefore = readFileSync(credsFile, "utf8");
  res = await fetch(`${base}/dsh-gateway/config/credentials`, {
    method: "PUT",
    headers: { "content-type": "text/plain", cookie: `dsh_session=${token}` },
    body: "users: [unclosed",
  });
  assert.equal(res.status, 400);
  assert.equal(readFileSync(credsFile, "utf8"), credsBefore);
  ok("config editor rejects invalid YAML without touching the file");

  // valid document without admin → 400
  res = await fetch(`${base}/dsh-gateway/config/credentials`, {
    method: "PUT",
    headers: { "content-type": "text/plain", cookie: `dsh_session=${token}` },
    body: "users:\n  - username: bob\n    password: x\n",
  });
  assert.equal(res.status, 400);
  ok("config editor rejects a user list without admin");

  // valid save → 200, file replaced, new credentials log in immediately
  res = await fetch(`${base}/dsh-gateway/config/credentials`, {
    method: "PUT",
    headers: { "content-type": "text/plain", cookie: `dsh_session=${token}` },
    body: "# edited via config editor\nusers:\n  - username: admin\n    password: newpass\n",
  });
  assert.equal(res.status, 200);
  const saved = readFileSync(credsFile, "utf8");
  assert.match(saved, /newpass/);
  res = await post("/login", "username=admin&password=newpass");
  assert.equal(res.status, 303);
  const newToken = res.headers.get("set-cookie").match(/dsh_session=([0-9a-f]+)/)[1];
  ok("config editor saves the file; new credentials take effect immediately");

  // logout clears the session
  res = await fetch(`${base}/logout`, { headers: { cookie: `dsh_session=${newToken}` }, redirect: "manual" });
  assert.equal(res.status, 303);
  res = await fetch(`${base}/api/ping`, { headers: { cookie: `dsh_session=${newToken}` } });
  assert.equal(res.status, 401);
  ok("logout invalidates the session");

  await gateway.close();
  await new Promise((resolve) => upstream.close(resolve));
  await new Promise((resolve) => wss.close(resolve));
  sessions.close();
  throttle.close();
}

// ── 5. HTTPS listener (TLS) ─────────────────────────────────────────────────
{
  const dir = mkdtempSync(path.join(tmpdir(), "dsh-tls-"));
  const certFile = path.join(dir, "cert.pem");
  const keyFile = path.join(dir, "key.pem");
  const { cert, key } = generateSelfSignedCert({ days: 2, hosts: ["DNS:localhost", "IP:127.0.0.1"] });
  writeFileSync(certFile, cert);
  writeFileSync(keyFile, key);
  const sessions = new SessionStore(24 * 3600 * 1000);
  const throttle = new LoginThrottle({ maxAttempts: 3, windowSeconds: 600, lockoutSeconds: 600 });
  const credsFile = path.join(dir, "creds.yaml");
  writeFileSync(credsFile, "users:\n  - username: admin\n    password: tls-pass\n");
  const gateway = createGateway({
    logger: { info: () => {} },
    credentialsFile: credsFile,
    sessionStore: sessions,
    throttle,
    tls: { cert, key },
    getUpstream: () => ({ host: "127.0.0.1", port: 1 }),
  });
  const addr = await gateway.listen("127.0.0.1", 0, 0);
  assert.ok(addr.httpsPort !== null, "https port assigned");

  const httpsGet = (urlPath, headers = {}) => new Promise((resolve, reject) => {
    https.get({
      host: "127.0.0.1",
      port: addr.httpsPort,
      path: urlPath,
      headers,
      rejectUnauthorized: false,
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    }).on("error", reject);
  });

  let got = await httpsGet("/login");
  assert.equal(got.status, 200);
  assert.match(got.body, /用户名/);
  ok("HTTPS login page served over TLS");

  got = await httpsGet("/api/probe");
  assert.equal(got.status, 401);
  ok("HTTPS unauthenticated API → 401 JSON");

  // login over HTTPS and confirm the cookie + 303
  got = await new Promise((resolve, reject) => {
    const body = "username=admin&password=tls-pass";
    const req = https.request({
      host: "127.0.0.1",
      port: addr.httpsPort,
      path: "/login",
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "content-length": Buffer.byteLength(body) },
      rejectUnauthorized: false,
    }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode, setCookie: res.headers["set-cookie"]?.[0] ?? "" }));
    });
    req.on("error", reject);
    req.end(body);
  });
  assert.equal(got.status, 303);
  assert.match(got.setCookie, /^dsh_session=/);
  ok("HTTPS login issues session cookie");

  // settings-page port change: rebind the TLS listener live
  const oldPort = addr.httpsPort;
  const newPort = await gateway.setHttpsPort("127.0.0.1", 0);
  assert.notEqual(newPort, oldPort);
  const refused = await new Promise((resolve) => {
    https.get({ host: "127.0.0.1", port: oldPort, path: "/login", rejectUnauthorized: false }, () => resolve(false))
      .on("error", () => resolve(true));
  });
  assert.equal(refused, true);
  const rebound = await new Promise((resolve, reject) => {
    https.get({ host: "127.0.0.1", port: newPort, path: "/login", rejectUnauthorized: false }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    }).on("error", reject);
  });
  assert.equal(rebound, 200);
  ok("HTTPS listener rebinds live on port change");

  await gateway.close();
  sessions.close();
  throttle.close();
}

console.log(`\nall ${passed} checks passed`);
