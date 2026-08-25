#!/usr/bin/env node
// dsh-remote-gateway — apply the loopback-trust patch to the SERVED
// @deepseek-ai/dsh-client-connection client bundle.
//
// Why: the harness computes ctx.connection.isLoopback from the page location,
// so a browser that reaches the UI through this gateway (a remote hostname)
// is "not loopback" and the settings pages refuse to work — the Models page
// fails with "加载提供方目录失败: settings are unavailable in this browser".
// The gateway injects window.__DSH_AUTH_GATEWAY__ into every proxied HTML
// document BEFORE the shell scripts run (the marker script is spliced right
// after <head>). This script patches the client bundle the harness actually
// serves (/plugins/@deepseek-ai/dsh-client-connection/client.js — read from
// node_modules on every request with a content-hash rev, so the change is
// live after a page refresh) so that the marker counts as loopback trust:
//   isLoopback: … || globalThis.__DSH_AUTH_GATEWAY__ === true,
//
// The harness /api trust fence accepts the resulting settings RPCs because
// the gateway already rewrites Host and Origin to the loopback authority.
//
// Idempotent: re-running is a no-op. Re-apply after any global dsh upgrade
// (npm i -g @deepseek-ai/dsh replaces the bundle). The dev watcher
// (scripts/dev.mjs) runs this automatically on every sync.
import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const NEEDLE = "isLoopback: pageLocation === void 0 || isLoopbackHostname(pageLocation.hostname),";
const REPLACEMENT = "isLoopback: pageLocation === void 0 || isLoopbackHostname(pageLocation.hostname) || globalThis.__DSH_AUTH_GATEWAY__ === true,";
const MARKER_TOKEN = "__DSH_AUTH_GATEWAY__";

const home = process.env.DSH_HOME?.trim() !== undefined && process.env.DSH_HOME.trim() !== ""
  ? process.env.DSH_HOME.trim()
  : path.join(homedir(), ".dsh");
const profile = process.env.DSH_WEB_AUTH_PROFILE ?? "web";

/** Where the running harness may resolve @deepseek-ai/dsh-client-connection from. */
function candidates() {
  const out = [];
  // 1. a profile-local copy (when the harness resolves from there)
  out.push(path.join(home, "profiles", profile, "node_modules", "@deepseek-ai", "dsh-client-connection", "lib", "client.js"));
  // 2. the global dsh install the CLI runs from (usual case): derive from the
  //    `dsh` shim location, mirroring scripts/dev.mjs's resolveDshBin.
  const which = spawnSync(process.platform === "win32" ? "where.exe" : "which", ["dsh"], { encoding: "utf8" });
  const dshDirs = [];
  if (which.error === undefined && which.status === 0) {
    for (const line of which.stdout.split(/\r?\n/)) {
      const shim = line.trim();
      if (shim === "") continue;
      dshDirs.push(path.join(path.dirname(shim), "node_modules", "@deepseek-ai", "dsh"));
      dshDirs.push(path.join(path.dirname(shim), "..", "node_modules", "@deepseek-ai", "dsh"));
    }
  }
  if (process.env.APPDATA !== undefined && process.env.APPDATA !== "") {
    dshDirs.push(path.join(process.env.APPDATA, "npm", "node_modules", "@deepseek-ai", "dsh"));
  }
  for (const dir of dshDirs) {
    out.push(path.join(dir, "node_modules", "@deepseek-ai", "dsh-client-connection", "lib", "client.js"));
  }
  return out;
}

const file = candidates().find((candidate) => existsSync(candidate));
if (file === undefined) {
  process.stderr.write("[patch-dsh-client] 找不到 @deepseek-ai/dsh-client-connection 的客户端包（已检查 profile 与全局 dsh 安装）\n");
  process.exit(1);
}

let text;
try {
  text = readFileSync(file, "utf8");
} catch (err) {
  process.stderr.write(`[patch-dsh-client] 读取 ${file} 失败：${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}

if (text.includes(MARKER_TOKEN)) {
  process.stdout.write(`[patch-dsh-client] ${file}\n  已打过补丁（标记已存在），无需处理。\n`);
  process.exit(0);
}

const occurrences = text.split(NEEDLE).length - 1;
if (occurrences !== 1) {
  process.stderr.write(`[patch-dsh-client] ${file}\n  客户端包内容与预期不匹配（找到 ${String(occurrences)} 处待替换源码）——\n  安装的 dsh-client-connection 可能已升级。请手动修改：让 isLoopback 在\n  globalThis.__DSH_AUTH_GATEWAY__ === true 时也为 true。\n`);
  process.exit(1);
}

// Back up the pristine bundle once, so an upgrade can be diffed/restored.
const backup = `${file}.dsh-gateway.bak`;
if (!existsSync(backup)) {
  try {
    copyFileSync(file, backup);
  } catch { /* backup is best effort */ }
}

try {
  writeFileSync(file, text.replace(NEEDLE, REPLACEMENT), "utf8");
} catch (err) {
  process.stderr.write(`[patch-dsh-client] 写入 ${file} 失败：${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}

process.stdout.write(`[patch-dsh-client] ${file}\n  已打补丁：__DSH_AUTH_GATEWAY__ 标记现在计为回环信任（设置页远程可用）。\n  刷新浏览器页面即可生效；原始备份：${backup}\n`);
