// dsh-login-gateway — the login page. One self-contained HTML document:
// no external assets, inline CSS/JS only, so it works from any network.
const ERROR_MESSAGES = {
  invalid: "用户名或密码错误",
  locked: "登录尝试次数过多，请稍后再试",
  malformed: "请求格式错误",
  required: "请输入用户名和密码",
};

/** Minimal HTML escaping for values interpolated into the page. */
function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * Render the login page.
 * @param options.title - brand title.
 * @param options.error - one of the ERROR_MESSAGES keys (or null).
 * @param options.sessionHours - session validity, shown as a note.
 */
export function loginPageHtml({ title = "DeepSeek Harness", error = null, sessionHours = 24 }) {
  const message = ERROR_MESSAGES[error] ?? null;
  const safeTitle = escapeHtml(title);
  const safeMessage = escapeHtml(message ?? "");
  const safeHours = escapeHtml(sessionHours);
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>登录 — ${safeTitle}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    background: radial-gradient(1200px 700px at 70% -10%, #1c2b46 0%, #0d1117 55%, #06090f 100%);
    color: #e6edf3;
  }
  .card {
    width: min(380px, calc(100vw - 32px));
    background: rgba(22, 27, 34, 0.9);
    border: 1px solid #30363d;
    border-radius: 14px;
    padding: 36px 32px 28px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.5);
  }
  .brand { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .logo {
    width: 38px; height: 38px; border-radius: 10px; flex: none;
    background: linear-gradient(135deg, #4d6bfe, #2563eb);
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: 20px; color: #fff;
  }
  h1 { font-size: 20px; font-weight: 600; }
  .subtitle { color: #8b949e; font-size: 13px; margin: 2px 0 22px; }
  label { display: block; font-size: 13px; color: #c9d1d9; margin: 14px 0 6px; }
  input {
    width: 100%; padding: 10px 12px; font-size: 15px;
    color: #e6edf3; background: #0d1117;
    border: 1px solid #30363d; border-radius: 8px; outline: none;
  }
  input:focus { border-color: #4d6bfe; box-shadow: 0 0 0 3px rgba(77, 107, 254, 0.25); }
  button {
    width: 100%; margin-top: 22px; padding: 11px; font-size: 15px; font-weight: 600;
    color: #fff; background: #2563eb; border: 0; border-radius: 8px; cursor: pointer;
  }
  button:hover { background: #1d4ed8; }
  .error {
    display: ${message ? "block" : "none"};
    margin-top: 16px; padding: 9px 12px; font-size: 13px;
    color: #ffa198; background: rgba(248, 81, 73, 0.12);
    border: 1px solid rgba(248, 81, 73, 0.4); border-radius: 8px;
  }
  .note { margin-top: 20px; font-size: 12px; color: #6e7681; text-align: center; }
</style>
</head>
<body>
  <form class="card" method="post" action="/login" autocomplete="on">
    <div class="brand">
      <div class="logo">D</div>
      <h1>${safeTitle}</h1>
    </div>
    <div class="subtitle">远程登录 · 请使用您的账号和密码</div>
    <label for="username">用户名</label>
    <input id="username" name="username" type="text" required autofocus autocomplete="username">
    <label for="password">密码</label>
    <input id="password" name="password" type="password" required autocomplete="current-password">
    <input type="hidden" name="next" id="next" value="/">
    <button type="submit">登 录</button>
    <div class="error" role="alert">${safeMessage}</div>
    <div class="note">登录有效期为 ${safeHours} 小时，每次打开浏览器均需重新登录</div>
  </form>
  <script>
    // Carry the original target path through the login round-trip
    // (same-origin relative paths only, to avoid open redirects).
    try {
      var params = new URLSearchParams(location.search);
      var next = params.get("next");
      if (next && next.charAt(0) === "/" && next.slice(0, 2) !== "//") {
        document.getElementById("next").value = next;
      }
    } catch (e) {}
  </script>
</body>
</html>`;
}
