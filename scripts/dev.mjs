#!/usr/bin/env node
// dsh-login-gateway dev watcher — "每次更改都自动打包".
//
// Watches this checkout (lib/**, package.json, cordis.patch.yml) and on every
// change re-syncs the plugin into the web profile so a running harness picks
// the edit up. Usage:
//
//   npm run dev            # ensure installed, then watch and auto-sync
//   npm run dev -- --once  # sync once and exit (CI / one-shot)
//   npm run dev -- --profile web
//
// How profile installs actually work (verified on a hoisted-linker profile):
// pnpm installs `file:` dependencies as a COPY of the directory — not a
// junction — and a plain `pnpm add` skips the copy when it considers the
// dependency "up to date", so source edits never reach the running harness
// without an explicit re-copy. This watcher therefore:
//   1. runs `dsh plugin --profile <name> add file:<repo>` only when the
//      plugin is missing from the profile, or package.json changed (keeps
//      the dependency row, bundle list and lockfile reconciled);
//   2. mirrors this checkout's runtime files (lib/**, package.json,
//      cordis.patch.yml, README.md) straight into the installed copy;
//   3. re-applies scripts/patch-dsh-client.mjs, so the served
//      dsh-client-connection bundle keeps honoring the gateway's
//      __DSH_AUTH_GATEWAY__ marker (the remote-settings fix; DSH upgrades
//      wipe it, hence the re-apply on every pack).
// The harness serves client plugins per-request with a content-hash rev and
// hot-reloads server entries via HMR, so a synced edit is picked up by the
// running GUI immediately (refresh the page for the browser half).
import { cpSync, existsSync, readFileSync, rmSync, watch, watchFile } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const argv = process.argv.slice(2);
const once = argv.includes("--once");
const flagValue = (name) => {
  const at = argv.indexOf(name);
  return at !== -1 && argv[at + 1] !== undefined ? argv[at + 1] : undefined;
};
const profile = flagValue("--profile") ?? process.env.DSH_WEB_AUTH_PROFILE ?? "web";
const packageName = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).name;
const home = process.env.DSH_HOME?.trim() !== undefined && process.env.DSH_HOME.trim() !== ""
  ? process.env.DSH_HOME.trim()
  : path.join(homedir(), ".dsh");
const profileDir = path.join(home, "profiles", profile);

const WATCH_FILES = [path.join(root, "package.json"), path.join(root, "cordis.patch.yml")];
const WATCH_DIRS = [path.join(root, "lib")];
/** Files mirrored into the profile's installed copy on every pack. */
const SYNC_ENTRIES = ["lib", "package.json", "cordis.patch.yml", "README.md"];

const now = () => new Date().toLocaleTimeString("zh-CN", { hour12: false });
const log = (...args) => console.log(`[${now()}]`, ...args);

/** Whether the plugin is currently a bundle layer of the profile. */
function isInstalled() {
  try {
    const manifest = JSON.parse(readFileSync(path.join(profileDir, "package.json"), "utf8"));
    return Array.isArray(manifest.dsh?.profile?.bundles) && manifest.dsh.profile.bundles.includes(packageName);
  } catch {
    return false;
  }
}

/**
 * Locate the dsh CLI entry (global npm install) without going through cmd
 * shims: `where dsh` / `which dsh` gives the shim path, from which the
 * package dir is derived; APPDATA/npm is the Windows fallback.
 * @returns absolute path of @deepseek-ai/dsh/lib/bin.js, or null.
 */
function resolveDshBin() {
  const candidates = [];
  const which = spawnSync(process.platform === "win32" ? "where.exe" : "which", ["dsh"], { encoding: "utf8" });
  if (which.error === undefined && which.status === 0) {
    for (const line of which.stdout.split(/\r?\n/)) {
      const shim = line.trim();
      if (shim === "") continue;
      candidates.push(path.join(path.dirname(shim), "node_modules", "@deepseek-ai", "dsh", "lib", "bin.js"));
      candidates.push(path.join(path.dirname(shim), "..", "node_modules", "@deepseek-ai", "dsh", "lib", "bin.js"));
    }
  }
  if (process.env.APPDATA !== undefined && process.env.APPDATA !== "") {
    candidates.push(path.join(process.env.APPDATA, "npm", "node_modules", "@deepseek-ai", "dsh", "lib", "bin.js"));
  }
  return candidates.find((candidate) => existsSync(candidate)) ?? null;
}

/** Run one child process to completion; resolves the exit code. */
function runChild(executable, args) {
  return new Promise((resolve) => {
    const child = spawn(executable, args, { stdio: "inherit" });
    child.on("error", (err) => {
      log(`子进程启动失败：${err instanceof Error ? err.message : String(err)}`);
      resolve(-1);
    });
    child.on("exit", (code) => resolve(code === null ? -1 : code));
  });
}

/** `dsh plugin --profile <name> add file:<repo>` (install / reconcile). */
async function pnpmAdd() {
  const bin = resolveDshBin();
  if (bin === null) {
    log("找不到 dsh CLI（全局 npm 安装的 @deepseek-ai/dsh）——请先安装 dsh 后再试");
    return false;
  }
  const args = [bin, "plugin", "--profile", profile, "add", `file:${root}`];
  log(`打包（pnpm add）→ ${process.execPath} ${args.join(" ")}`);
  const code = await runChild(process.execPath, args);
  log(`pnpm add 完成（exit=${code}）`);
  return code === 0;
}

/** Mirror this checkout's runtime files into the profile's installed copy. */
function syncInstalledCopy() {
  const target = path.join(profileDir, "node_modules", packageName);
  if (!existsSync(target)) {
    log(`安装目录不存在：${target}`);
    return false;
  }
  for (const entry of SYNC_ENTRIES) {
    rmSync(path.join(target, entry), { recursive: true, force: true });
    cpSync(path.join(root, entry), path.join(target, entry), { recursive: true });
  }
  log(`已同步 ${SYNC_ENTRIES.length} 项 → ${target}`);
  return true;
}

/**
 * Re-apply the loopback-trust patch to the served dsh-client-connection
 * bundle (see scripts/patch-dsh-client.mjs). The harness reads that bundle
 * from node_modules per request with a content-hash rev, so a patched file is
 * picked up on the next page refresh — no restart needed. DSH upgrades wipe
 * the patch, hence the re-apply on every pack. Non-fatal: the gateway keeps
 * working, only the remote settings pages stay disabled.
 */
async function patchClientBundle() {
  const script = path.join(root, "scripts", "patch-dsh-client.mjs");
  if (!existsSync(script)) return true;
  const code = await runChild(process.execPath, [script]);
  if (code !== 0) {
    log("警告：dsh-client-connection 补丁未应用——远程设置页（settings are unavailable in this browser）不会修复，详情见上方输出");
    return false;
  }
  return true;
}

/**
 * The pack step: install/reconcile when needed, then always mirror the
 * checkout into the profile's copy (hoisted linker installs `file:` deps as
 * a copy, so plain `pnpm add` alone never propagates content changes).
 * @param changed - the files that triggered this pack (for diagnostics).
 */
async function pack(changed = []) {
  const manifestChanged = changed.some((file) => path.basename(file) === "package.json");
  if (!isInstalled() || manifestChanged) {
    if (!(await pnpmAdd())) return false;
  } else {
    log("已安装且 package.json 未变：跳过 pnpm add，直接同步文件拷贝…");
  }
  const synced = syncInstalledCopy();
  if (synced) await patchClientBundle();
  return synced;
}

/** Print what changed and what it takes for it to show up in a running GUI. */
function report(changed) {
  const client = changed.some((file) => path.basename(file) === "client.js");
  const server = changed.some((file) => path.basename(file) !== "client.js");
  if (client) log("client.js 已同步：刷新浏览器页面即可看到新版本（内容哈希 rev 已更新）");
  if (server) log("服务端文件已同步：Harness HMR 会热载；未生效时重启 dsh web 使 plugin apply() 重新执行");
}

// ── main ────────────────────────────────────────────────────────────────────
log(`dsh-login-gateway dev watcher — profile: ${profile}`);
log(`仓库：${root}`);
if (once) {
  log("--once：执行一次打包后退出…");
  const ok = await pack();
  log(ok ? "--once：打包完成，退出" : "--once：打包失败（exit=1）");
  process.exit(ok ? 0 : 1);
}
if (!isInstalled()) {
  log(`插件尚未安装到 profile "${profile}"，先执行首次打包…`);
  await pack();
} else {
  log(`插件已在 profile "${profile}"（bundles 列表包含 ${packageName}）`);
}

// Debounced watch: coalesce bursts of file events into one pack run.
let timer = null;
let pending = [];
const schedule = (file) => {
  pending.push(file);
  if (timer !== null) clearTimeout(timer);
  timer = setTimeout(async () => {
    const changed = [...new Set(pending)];
    pending = [];
    timer = null;
    log(`检测到 ${changed.length} 个文件变更：${changed.map((f) => path.relative(root, f)).join(", ")}`);
    const ok = await pack(changed);
    if (ok) report(changed);
  }, 300);
};

for (const dir of WATCH_DIRS) {
  if (!existsSync(dir)) continue;
  const watcher = watch(dir, { recursive: true }, (_event, filename) => {
    if (filename !== null && filename !== undefined) schedule(path.join(dir, filename.toString()));
  });
  watcher.on("error", (err) => log(`监视 ${dir} 出错：${err instanceof Error ? err.message : String(err)}`));
  log(`监视中：${path.relative(root, dir)}/**`);
}
for (const file of WATCH_FILES) {
  watchFile(file, { interval: 400 }, () => schedule(file));
  log(`监视中：${path.relative(root, file)}`);
}
log("按 Ctrl+C 退出。改动会自动同步到 profile；浏览器端刷新页面即可，服务端由 HMR 热载（必要时重启 dsh web）。");
