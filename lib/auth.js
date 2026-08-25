// dsh-remote-gateway — authentication core: credentials file loading and
// verification, the in-memory session token store (24h TTL), and a small
// login-attempt throttle.
import { createHash, randomBytes, timingSafeEqual, webcrypto } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import yaml from "js-yaml";

/** Generate a strong random password for a default account. */
export function generatePassword(length = 20) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*-_=+";
  const bytes = new Uint8Array(length);
  webcrypto.getRandomValues(bytes);
  let out = "";
  for (const byte of bytes) out += alphabet[byte % alphabet.length];
  return out;
}

/** Lowercase hex SHA-256 of a string (used for both stored and attempted passwords). */
export function sha256Hex(text) {
  return createHash("sha256").update(String(text ?? ""), "utf8").digest("hex");
}

/** Constant-time comparison of two hex digest strings. */
export function safeEqualHex(a, b) {
  const ab = Buffer.from(String(a ?? ""), "utf8");
  const bb = Buffer.from(String(b ?? ""), "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/**
 * Load the user list from the credentials YAML file.
 *
 * Expected shape:
 * ```yaml
 * users:
 *   - username: admin
 *     password: "plain-text-password"
 *     # or, instead of password:
 *     # passwordHash: "sha256:<64 hex chars>"
 * ```
 * The file is re-read on every login attempt, so edits apply immediately
 * without restarting the gateway.
 * @param file - absolute path of the credentials file.
 * @returns {users, error} — error describes a missing/unparsable file.
 */
export function loadUsers(file) {
  let raw;
  try {
    raw = readFileSync(file, "utf8");
  } catch (err) {
    return { users: [], error: `cannot read credentials file ${file}: ${err instanceof Error ? err.message : String(err)}` };
  }
  let doc;
  try {
    doc = yaml.load(raw) ?? {};
  } catch (err) {
    return { users: [], error: `credentials file ${file} is not valid YAML: ${err instanceof Error ? err.message : String(err)}` };
  }
  const users = Array.isArray(doc.users) ? doc.users : [];
  return { users };
}

/**
 * Verify a username/password pair against the loaded user list.
 * Accepts plain `password` or `passwordHash: "sha256:<hex>"` per user; when
 * both are present the hash wins. Unknown users answer false exactly like a
 * wrong password (no user enumeration).
 */
export function verifyUser(users, username, password) {
  const wanted = String(username ?? "");
  const user = users.find((entry) => entry !== null && typeof entry === "object" && String(entry.username ?? "") === wanted);
  if (user === undefined) return false;
  const attempt = sha256Hex(password);
  if (typeof user.passwordHash === "string" && user.passwordHash.trim() !== "") {
    const match = /^sha256:([0-9a-f]{64})$/i.exec(user.passwordHash.trim());
    if (match === null) return false;
    return safeEqualHex(attempt, match[1].toLowerCase());
  }
  if (typeof user.password === "string") return safeEqualHex(attempt, sha256Hex(user.password));
  return false;
}

/**
 * Validate an account list coming from the settings page: every account needs
 * a non-empty username, usernames must be unique, and the `admin` account is
 * always required. Throws an Error describing the first violation.
 */
export function validateUsersList(users) {
  const seen = new Set();
  for (const entry of users ?? []) {
    const name = String(entry?.username ?? "").trim();
    if (name === "") throw new Error("web-auth: every account needs a non-empty username");
    if (seen.has(name)) throw new Error(`web-auth: duplicate account "${name}"`);
    seen.add(name);
  }
  if (!seen.has("admin")) throw new Error('web-auth: the "admin" account is required and cannot be removed');
  return true;
}

/**
 * Validate a trusted-domain rule list; throws on the first violation.
 * Rules are comma-separated entries: "*", "host", "host:port", "*.suffix".
 */
export function validateTrustedDomainsList(list) {
  if (list.length === 0) throw new Error("web-auth: 信任域不能为空（填 * 表示不限制）");
  for (const rule of list) {
    if (!/^[^\s/]+$/.test(rule)) {
      throw new Error(`web-auth: 信任域 "${rule}" 格式无效（不能含空格或 /）`);
    }
  }
  return true;
}

/** Serialize a full credentials document (header + YAML) with mode 0600. */
function writeUsersDoc(file, doc) {
  const text = "# DeepSeek Harness web 登录凭据（由设置页或 dsh-web-auth CLI 管理）\n"
    + "# 修改后立即生效，无需重启。password 为明文；workDir 限制该账号的工作目录；\n"
    + "# gateway 段保存 httpsPort 与 trustedDomains（信任域）。\n"
    + yaml.dump(doc, { lineWidth: 120 });
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, text, { mode: 0o600 });
}

/**
 * Persist the account list to the credentials YAML file (mode 600). Other
 * top-level sections (e.g. the gateway: settings block) are preserved.
 * @param file - absolute credentials file path.
 * @param users - [{username, password, workDir?}] rows to store.
 */
export function writeUsersFile(file, users) {
  const rows = users.map((entry) => ({
    username: String(entry.username ?? ""),
    ...(typeof entry.password === "string" && entry.password !== "" ? { password: entry.password } : {}),
    ...(typeof entry.workDir === "string" && entry.workDir.trim() !== "" ? { workDir: entry.workDir.trim() } : {}),
  }));
  let extra = {};
  try {
    const doc = yaml.load(readFileSync(file, "utf8")) ?? {};
    if (doc !== null && typeof doc === "object" && !Array.isArray(doc)) {
      const { users: _dropped, ...rest } = doc;
      extra = rest;
    }
  } catch { /* first write */ }
  writeUsersDoc(file, { ...extra, users: rows });
}

/** The primary account: "admin" when present, else the first named user. */
function primaryUser(users) {
  return users.find((u) => u !== null && typeof u === "object" && String(u.username ?? "") === "admin")
    ?? users.find((u) => u !== null && typeof u === "object" && typeof u.username === "string" && u.username !== "");
}

/**
 * Read the primary account and the gateway settings (httpsPort /
 * trustedDomains) from the credentials document. Absent values come back as
 * null / "" so the caller can fall back to its own defaults.
 */
export function loadPrimarySettings(file) {
  let doc = {};
  try {
    doc = yaml.load(readFileSync(file, "utf8")) ?? {};
  } catch { /* missing/unparsable → defaults */ }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) doc = {};
  const users = Array.isArray(doc.users) ? doc.users : [];
  const primary = primaryUser(users);
  const gateway = doc.gateway !== null && typeof doc.gateway === "object" && !Array.isArray(doc.gateway) ? doc.gateway : {};
  return {
    username: primary === undefined ? "" : String(primary.username),
    httpsPort: Number.isInteger(gateway.httpsPort) ? gateway.httpsPort : null,
    trustedDomains: Array.isArray(gateway.trustedDomains) ? gateway.trustedDomains.map((rule) => String(rule)) : null,
  };
}

/**
 * Apply primary-account + gateway-settings edits coming from the settings
 * endpoint (the gear-menu form). Everything is validated before anything is
 * written; the gateway section of the document is updated atomically.
 * @returns {{error?: string, value?: {username, httpsPort, trustedDomains}}}
 */
export function applyGatewaySettings(file, { username, password, httpsPort, trustedDomains }) {
  const nextUsername = String(username ?? "").trim();
  if (nextUsername === "") return { error: "web-auth: 用户名不能为空" };
  const wantPort = Number(httpsPort);
  if (!Number.isInteger(wantPort) || wantPort < 1 || wantPort > 65535) {
    return { error: "web-auth: 端口必须是 1–65535 的整数" };
  }
  const rules = (Array.isArray(trustedDomains) ? trustedDomains : [String(trustedDomains ?? "")])
    .map((rule) => String(rule).trim())
    .filter((rule) => rule !== "");
  try {
    validateTrustedDomainsList(rules);
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
  let doc = {};
  try {
    doc = yaml.load(readFileSync(file, "utf8")) ?? {};
  } catch { /* first write */ }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) doc = {};
  const users = Array.isArray(doc.users) ? doc.users : [];
  const primary = primaryUser(users);
  const primaryIdx = users.findIndex((u) => u === primary);
  const passwordText = typeof password === "string" ? password : "";
  if (primaryIdx >= 0) {
    const others = users
      .filter((u, i) => i !== primaryIdx && u !== null && typeof u === "object" && typeof u.username === "string" && u.username !== "")
      .map((u) => String(u.username));
    if (others.includes(nextUsername)) return { error: `web-auth: 用户名 "${nextUsername}" 已被其他账号使用` };
    const row = { ...users[primaryIdx], username: nextUsername };
    if (passwordText !== "") row.password = passwordText;
    users[primaryIdx] = row;
  } else {
    if (passwordText === "") return { error: "web-auth: 新账号需要密码" };
    users.push({ username: nextUsername, password: passwordText });
  }
  try {
    writeUsersDoc(file, { ...doc, users, gateway: { httpsPort: wantPort, trustedDomains: rules } });
  } catch (err) {
    return { error: `web-auth: 写入失败：${err instanceof Error ? err.message : String(err)}` };
  }
  return { value: { username: nextUsername, httpsPort: wantPort, trustedDomains: rules } };
}

/**
 * Atomically save a credentials YAML document edited in the config editor.
 * The text is validated before anything is written: it must parse as YAML
 * with a `users` list that satisfies {@link validateUsersList}. The user's
 * formatting is preserved verbatim (the editor owns the file content).
 * @param file - absolute credentials file path.
 * @param text - the full YAML document to persist.
 * @returns {{error?: string}} — error describes the validation/write failure.
 */
export function saveCredentialsText(file, text) {
  const raw = String(text ?? "");
  if (raw.trim() === "") return { error: "web-auth: 配置文件不能为空" };
  let doc;
  try {
    doc = yaml.load(raw);
  } catch (err) {
    return { error: `web-auth: 配置不是有效的 YAML：${err instanceof Error ? err.message : String(err)}` };
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    return { error: "web-auth: 配置顶层必须是包含 users 列表的对象" };
  }
  if (!Array.isArray(doc.users)) {
    return { error: 'web-auth: 配置缺少 "users" 列表' };
  }
  try {
    validateUsersList(doc.users);
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
  try {
    mkdirSync(dirname(file), { recursive: true });
    const tmp = `${file}.tmp-${process.pid}-${Date.now()}`;
    writeFileSync(tmp, raw, { mode: 0o600 });
    renameSync(tmp, file);
  } catch (err) {
    return { error: `web-auth: 写入失败：${err instanceof Error ? err.message : String(err)}` };
  }
  return {};
}

/**
 * In-memory session token store. Tokens are random 256-bit hex strings that
 * expire `ttlMs` after issuance. The store is deliberately memory-only: a
 * gateway restart logs everyone out, which matches the "every session must
 * log in" requirement.
 */
export class SessionStore {
  constructor(ttlMs) {
    this.ttlMs = ttlMs;
    this.map = new Map();
    const sweepEvery = Math.max(1000, Math.min(ttlMs, 60_000));
    this.timer = setInterval(() => this.sweep(), sweepEvery);
    if (typeof this.timer.unref === "function") this.timer.unref();
  }
  /** Mint a token for `username`, valid for ttlMs. */
  create(username) {
    const token = randomBytes(32).toString("hex");
    this.map.set(token, { username: String(username ?? ""), expiresAt: Date.now() + this.ttlMs });
    return token;
  }
  /** Resolve a token to its session, or null when absent/expired. */
  get(token) {
    if (typeof token !== "string" || token === "") return null;
    const session = this.map.get(token);
    if (session === undefined) return null;
    if (Date.now() > session.expiresAt) {
      this.map.delete(token);
      return null;
    }
    return session;
  }
  delete(token) {
    if (typeof token === "string") this.map.delete(token);
  }
  sweep() {
    const now = Date.now();
    for (const [token, session] of this.map) if (now > session.expiresAt) this.map.delete(token);
  }
  close() {
    clearInterval(this.timer);
    this.map.clear();
  }
}

/**
 * Per-client-IP login throttle: after `maxAttempts` failures within
 * `windowSeconds`, further attempts from that IP are refused for
 * `lockoutSeconds`. Successful logins reset the counters.
 */
export class LoginThrottle {
  constructor({ maxAttempts = 5, windowSeconds = 600, lockoutSeconds = 600, now = () => Date.now() }) {
    this.maxAttempts = maxAttempts;
    this.windowSeconds = windowSeconds;
    this.lockoutSeconds = lockoutSeconds;
    this.now = now;
    this.state = new Map();
    this.timer = setInterval(() => this.sweep(), Math.min(windowSeconds, 60_000) * 1000);
    if (typeof this.timer.unref === "function") this.timer.unref();
  }
  /** Seconds remaining in a lockout, or 0 when this client may try again. */
  blockedFor(key) {
    const entry = this.state.get(key);
    if (entry === undefined) return 0;
    const nowMs = this.now();
    if (entry.lockedUntil > nowMs) return Math.ceil((entry.lockedUntil - nowMs) / 1000);
    if (entry.fails >= this.maxAttempts && nowMs - entry.firstFail <= this.windowSeconds * 1000) {
      entry.lockedUntil = nowMs + this.lockoutSeconds * 1000;
      return this.lockoutSeconds;
    }
    return 0;
  }
  fail(key) {
    const nowMs = this.now();
    let entry = this.state.get(key);
    if (entry === undefined || nowMs - entry.firstFail > this.windowSeconds * 1000) {
      entry = { fails: 0, firstFail: nowMs, lockedUntil: 0 };
      this.state.set(key, entry);
    }
    entry.fails += 1;
    if (entry.fails >= this.maxAttempts) entry.lockedUntil = nowMs + this.lockoutSeconds * 1000;
  }
  success(key) {
    this.state.delete(key);
  }
  sweep() {
    const nowMs = this.now();
    for (const [key, entry] of this.state) {
      if (entry.lockedUntil <= nowMs && nowMs - entry.firstFail > this.windowSeconds * 1000) this.state.delete(key);
    }
  }
  close() {
    clearInterval(this.timer);
    this.state.clear();
  }
}
