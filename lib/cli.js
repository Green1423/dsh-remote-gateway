#!/usr/bin/env node
// dsh-web-auth CLI — manage the gateway credentials YAML file and TLS cert.
//
//   dsh-web-auth init --username admin [--password <pw>] [--force]
//   dsh-web-auth set-user [--username <name>] [--password <pw> | --password-hash sha256:<hex>]
//   dsh-web-auth list
//   dsh-web-auth hash <password>
//   dsh-web-auth gen-cert [--host <ip-or-name>]... [--days <n>] [--enable]
//
// set-user edits the CURRENT account ("admin", or the first named user when
// admin is absent): rename it and/or change its password. Adding or removing
// accounts is intentionally not part of the CLI — the account table lives in
// the YAML file and is managed through the gear menu's config editor.
//
// The default file is $DSH_HOME/web-auth.yaml (or ~/.dsh/web-auth.yaml).
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir, networkInterfaces } from "node:os";
import path from "node:path";
import yaml from "js-yaml";
import { generatePassword, sha256Hex } from "./auth.js";
import { generateSelfSignedCert } from "./cert.js";

const HEADER = `# DeepSeek Harness web 登录凭据（由 dsh-web-auth 管理）
# 修改后立即生效，无需重启。password 为明文；passwordHash 优先于 password。
# 生成哈希: dsh-web-auth hash <密码>
`;

function parseArgs(argv) {
  const args = { _: [], flags: {} };
  const setFlag = (key, value) => {
    // kebab-case CLI flags → camelCase keys (password-hash → passwordHash).
    args.flags[key.replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
  };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token.startsWith("--")) {
      const eq = token.indexOf("=");
      if (eq !== -1) {
        setFlag(token.slice(2, eq), token.slice(eq + 1));
        continue;
      }
      const key = token.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        setFlag(key, next);
        i += 1;
      } else {
        setFlag(key, true);
      }
    } else {
      args._.push(token);
    }
  }
  return args;
}

function defaultFile() {
  const home = process.env.DSH_HOME?.trim();
  return path.join(home !== undefined && home !== "" ? home : path.join(homedir(), ".dsh"), "web-auth.yaml");
}

function fail(message) {
  process.stderr.write(`dsh-web-auth: ${message}\n`);
  process.exit(1);
}

function loadDoc(file) {
  if (!existsSync(file)) return { users: [] };
  let raw;
  try {
    raw = readFileSync(file, "utf8");
  } catch (err) {
    fail(`cannot read ${file}: ${err.message}`);
  }
  try {
    const doc = yaml.load(raw) ?? {};
    if (!Array.isArray(doc.users)) doc.users = [];
    return doc;
  } catch (err) {
    fail(`${file} is not valid YAML: ${err.message}`);
  }
}

function saveDoc(file, doc) {
  try {
    mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp-${process.pid}`;
    writeFileSync(tmp, HEADER + yaml.dump(doc, { lineWidth: 120 }), { mode: 0o600 });
    writeFileSync(file, HEADER + yaml.dump(doc, { lineWidth: 120 }), { mode: 0o600 });
    try { unlinkSync(tmp); } catch { /* best effort */ }
  } catch (err) {
    fail(`cannot write ${file}: ${err.message}`);
  }
}

function usage() {
  process.stderr.write(`usage:
  dsh-web-auth init [--username <name>] [--password <pw>] [--work-dir <path>] [--force] [--file <path>]
  dsh-web-auth set-user [--username <name>] [--password <pw> | --password-hash sha256:<hex>] [--work-dir <path>] [--file <path>]
  dsh-web-auth list [--file <path>]
  dsh-web-auth hash <password>
  dsh-web-auth gen-cert [--host <ip-or-name>] [--days <n>] [--enable]

set-user edits the current account (admin, or the first named user when admin
is absent). At least one of --username / --password / --password-hash /
--work-dir is required. --password-hash wins over --password.
`);
  process.exit(2);
}

/** Default TLS certificate/key locations under the harness home. */
function defaultTls() {
  const home = process.env.DSH_HOME?.trim();
  const base = home !== undefined && home !== "" ? home : path.join(homedir(), ".dsh");
  return { certFile: path.join(base, "web-auth-cert.pem"), keyFile: path.join(base, "web-auth-key.pem") };
}

function lanIpv4s() {
  const out = [];
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === "IPv4" && !entry.internal) out.push(entry.address);
    }
  }
  return out;
}

const isIpLiteral = (value) => value.includes(":") || /^\d{1,3}(\.\d{1,3}){3}$/.test(value);

/** Generate a self-signed TLS certificate for the login gateway. */
function genCert(args) {
  const { certFile, keyFile } = defaultTls();
  const days = Number(args.flags.days ?? 3650) || 3650;
  const extras = (typeof args.flags.host === "string" ? args.flags.host.split(",") : [])
    .map((value) => value.trim())
    .filter((value) => value !== "");
  const sans = [
    "DNS:localhost",
    "IP:127.0.0.1",
    ...lanIpv4s().map((ip) => `IP:${ip}`),
    ...extras.map((value) => (isIpLiteral(value) ? `IP:${value}` : `DNS:${value}`)),
  ];
  const unique = [...new Set(sans)];
  if (existsSync(certFile) || existsSync(keyFile)) fail(`${certFile} or ${keyFile} already exists (delete them first to regenerate)`);
  try {
    mkdirSync(path.dirname(certFile), { recursive: true });
    const { cert, key } = generateSelfSignedCert({ days, hosts: unique });
    writeFileSync(certFile, cert, { mode: 0o644 });
    writeFileSync(keyFile, key, { mode: 0o600 });
  } catch (err) {
    fail(`certificate generation failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  process.stdout.write(`generated ${certFile}\n          ${keyFile} (SANs: ${unique.join(", ")})\n`);

  if (args.flags.enable === true) {
    const home = process.env.DSH_HOME?.trim();
    const profileDir = path.join(home !== undefined && home !== "" ? home : path.join(homedir(), ".dsh"), "profiles", "web");
    const patchFile = path.join(profileDir, "cordis.patch.yml");
    let rows = [];
    if (existsSync(patchFile)) {
      try {
        rows = yaml.load(readFileSync(patchFile, "utf8")) ?? [];
      } catch (err) {
        fail(`cannot parse ${patchFile}: ${err.message}`);
      }
    }
    if (!Array.isArray(rows)) fail(`${patchFile} must be a YAML array`);
    const config = {
      httpEnabled: false,
      httpsEnabled: true,
      httpsPort: 8443,
      httpsCertFile: certFile,
      httpsKeyFile: keyFile,
    };
    const existing = rows.find((row) => row !== null && typeof row === "object" && row.id === "remote-gateway");
    if (existing !== undefined) {
      existing.config = { ...(existing.config ?? {}), ...config };
    } else {
      rows.push({ id: "remote-gateway", config });
    }
    const header = `# Your patch layer for this dsh profile, applied after every bundle layer:
# a top-level YAML array of loader patch entries (id-targeted config
# overrides, disables, and insert lists; \`!!js\` expressions allowed).
`;
    try {
      mkdirSync(path.dirname(patchFile), { recursive: true });
      writeFileSync(patchFile, header + yaml.dump(rows, { lineWidth: 120 }));
    } catch (err) {
      fail(`cannot write ${patchFile}: ${err.message}`);
    }
    process.stdout.write(`enabled HTTPS in ${patchFile} — restart "dsh web" and visit https://<host>:8443\n`);
  }
}

const args = parseArgs(process.argv.slice(2));
const command = args._[0];
const file = typeof args.flags.file === "string" && args.flags.file !== "" ? args.flags.file : defaultFile();

switch (command) {
  case "init": {
    if (existsSync(file) && args.flags.force !== true) fail(`${file} already exists (use --force to overwrite)`);
    const username = args.flags.username ?? "admin";
    const password = typeof args.flags.password === "string" ? args.flags.password : generatePassword();
    const user = { username, password };
    if (typeof args.flags.workDir === "string" && args.flags.workDir !== "") user.workDir = args.flags.workDir;
    saveDoc(file, { users: [user] });
    process.stdout.write(`created ${file} with user "${username}"\n`);
    if (typeof args.flags.password !== "string") process.stdout.write(`generated password: ${password}\n(store it somewhere safe; change it later with set-user)\n`);
    break;
  }
  case "set-user": {
    // Modify the CURRENT account ("admin", or the first named user when admin
    // is absent): rename it (--username) and/or change its password
    // (--password or --password-hash; the hash wins when both are given).
    const doc = loadDoc(file);
    const primary = doc.users.find((u) => u !== null && typeof u === "object" && String(u?.username ?? "") === "admin")
      ?? doc.users.find((u) => u !== null && typeof u === "object" && typeof u?.username === "string" && u.username !== "");
    if (primary === undefined) fail(`no account in ${file} (run "init" first)`);
    const hash = typeof args.flags.passwordHash === "string" && args.flags.passwordHash !== "" ? args.flags.passwordHash : null;
    const password = typeof args.flags.password === "string" && args.flags.password !== "" ? args.flags.password : null;
    const username = typeof args.flags.username === "string" && args.flags.username.trim() !== "" ? args.flags.username.trim() : null;
    const workDir = typeof args.flags.workDir === "string" && args.flags.workDir !== "" ? args.flags.workDir : null;
    if (hash === null && password === null && username === null && workDir === null) {
      fail("provide at least one of --username, --password, --password-hash or --work-dir");
    }
    if (hash !== null && !/^sha256:[0-9a-f]{64}$/i.test(hash)) {
      fail("--password-hash must look like sha256:<64 hex chars> (generate it with \"dsh-web-auth hash <password>\")");
    }
    if (username !== null) {
      const clash = doc.users.find((u) => u !== primary && u !== null && typeof u === "object" && String(u?.username ?? "") === username);
      if (clash !== undefined) fail(`account "${username}" already exists in ${file}`);
    }
    if (username !== null) primary.username = username;
    if (hash !== null) {
      primary.passwordHash = hash;
      delete primary.password; // the hash takes precedence; drop the stale plaintext
    } else if (password !== null) {
      primary.password = password;
      delete primary.passwordHash;
    }
    if (workDir !== null) primary.workDir = workDir;
    saveDoc(file, doc);
    process.stdout.write(`updated account "${primary.username}" in ${file}\n`);
    break;
  }
  case "list": {
    const doc = loadDoc(file);
    if (doc.users.length === 0) {
      process.stdout.write(`no users in ${file}\n`);
      break;
    }
    for (const user of doc.users) {
      const kind = typeof user?.passwordHash === "string" && user.passwordHash !== "" ? "password-hash" : "password";
      const workDir = typeof user?.workDir === "string" && user.workDir !== "" ? `, workDir=${user.workDir}` : "";
      process.stdout.write(`${user?.username} (${kind}${workDir})\n`);
    }
    break;
  }
  case "hash": {
    const password = args._[1];
    if (password === undefined) usage();
    process.stdout.write(`sha256:${sha256Hex(password)}\n`);
    break;
  }
  case "gen-cert": {
    genCert(args);
    break;
  }
  default:
    usage();
}
