# dsh-remote-gateway

为 DeepSeek Harness 的 Web 界面提供远程登录网关：账号密码登录页、24 小时会话、支持 `0.0.0.0` 绑定。

## 为什么是一个独立网关

Harness 的 Web 服务器刻意**拒绝 `--host 0.0.0.0`**（它会直接把远程代码执行暴露到网络），并且其 `/api` 信任围栏没有认证概念。本插件作为认证层运行在 Harness 前面：

```
浏览器 ──▶ 0.0.0.0:8080 (登录网关) ──▶ 127.0.0.1:<harness端口> (Harness Web)
              │ 需要账号密码登录                  │ 仅回环可达
              │ 会话 24 小时有效                  └ Host/Origin 重写为回环，通过信任围栏
```

- 网关绑定 `0.0.0.0`（默认 `:8080`），Harness 本体继续只绑定 `127.0.0.1`（纵深防御）。
- 未登录访问任何页面 → 跳转登录页；未登录访问 API/WebSocket → `401`。
- HTTP 与 WebSocket 均被代理，代理时把 `Host`/`Origin` 重写为回环地址，使 Harness 的信任围栏（包括仅限回环的配置面方法）正常放行；原始地址保留在 `X-Forwarded-Host`。

## 安装

```bash
dsh plugin --profile web add file:<本仓库路径>
```

安装后 `dsh --profile web` 启动时网关随 Harness 一起启动。默认配置：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `host` | `0.0.0.0` | 网关绑定地址 |
| `port` | `8080` | 网关端口 |
| `credentialsFile` | `$DSH_HOME/web-auth.yaml` | 账号密码配置文件 |
| `sessionTtlHours` | `24` | 登录有效时长（小时） |
| `cookiePersistent` | `false` | `false` = 浏览器会话级 Cookie（每次打开浏览器都要登录） |
| `maxLoginAttempts` / `lockoutSeconds` | `5` / `600` | 登录失败节流 |

## 开发：改动自动打包

仓库根目录运行 `npm run dev` 即可进入开发循环：**每次保存改动都会自动同步到 profile 的安装拷贝**（`lib/`、`package.json`、`cordis.patch.yml` 直接镜像到 `~/.dsh/profiles/web/node_modules/dsh-remote-gateway`；首次未安装或改过 `package.json` 时先执行 `dsh plugin --profile web add file:<本仓库>` 完成安装/调和）。

```bash
npm run dev            # 首次未安装会自动安装；之后监视变更并自动同步
npm run dev -- --once  # 只同步一次（CI 用）
npm run dev -- --profile web   # 指定 profile（默认 web）
```

说明：

- profile 的 pnpm 使用 `nodeLinker: hoisted`，`file:` 依赖是**拷贝**而非链接，且 pnpm 认为"已是最新"时不会重新拷贝——所以必须由 watcher 显式同步文件，光改仓库文件或重跑 `pnpm add` 都不会传到运行中的 Harness。
- **客户端改动**（`lib/client.js`）：GUI 按请求实时读取文件并以内容哈希做版本号，同步后**刷新页面**即可看到新版。
- **服务端改动**（`lib/` 下除 `client.js` 外的文件、`cordis.patch.yml`）：**必须重启 `dsh web`** 才生效（插件 `apply()` 在启动时执行；实测文件同步不会触发服务端热载）。
- **其他插件兼容性**：在 Harness 运行中热装的第三方插件（如 `dsh-vision-toolkit`）通常只有浏览器端生效，其服务端路由要等重启才注册——否则浏览器请求 `/_dsh/*` 会拿到 404 空响应，插件前端报 `Failed to execute 'json' on 'Response': Unexpected end of JSON input`。装完新插件请**重启 `dsh web`**。网关对这类路由的 Host/Origin 回环重写与插件自身的同源校验兼容（smoke 测试覆盖）。
- 需要 `dsh` 在 PATH 上（watcher 也会尝试全局 npm 安装的 dsh）。

在 `~/.dsh/profiles/web/cordis.patch.yml` 中覆盖配置：

```yaml
- id: remote-gateway
  config:
    host: 0.0.0.0
    port: 8443
    sessionTtlHours: 24
```

## 账号密码

凭据保存在 YAML 配置文件中（默认 `~/.dsh/web-auth.yaml`），修改后立即生效，无需重启：

```yaml
users:
  - username: admin
    password: "your-password"
    # 或使用哈希（优先于 password）：
    # passwordHash: "sha256:<64位hex>"
```

CLI 管理：

```bash
dsh-web-auth init                        # 创建文件并生成随机密码（会打印一次）
dsh-web-auth init --username admin --password 'S3cret!' --force
dsh-web-auth set-user --password 'S3cret!'                      # 修改当前账号的密码
dsh-web-auth set-user --username root --password 'S3cret!'      # 当前账号改名 + 改密码
dsh-web-auth set-user --password-hash sha256:$(dsh-web-auth hash 'p@ss' | cut -d: -f2)
dsh-web-auth list
dsh-web-auth hash 'p@ss'                 # 生成 sha256 哈希
```

`set-user` 修改**当前账号**（`admin`，或文件中第一个账号）：`--username` 改名、`--password` / `--password-hash` 改密码（哈希优先，且会清掉旧明文）、`--work-dir` 改工作目录限制，至少指定一项。CLI **不再提供添加/删除账号**（`add-user` / `remove-user` 已移除）——账号表的增删请使用齿轮菜单里的"编辑配置文件（web-auth.yaml）"，或直接编辑 YAML 文件。

## 登录行为

- 每次打开浏览器（新会话）都要求登录：会话 Cookie 是浏览器会话级的，不跨浏览器重启保存。
- 登录成功后有效期 24 小时（`sessionTtlHours`），到期后自动要求重新登录。
- `/logout` 立即注销。
- 令牌仅存于网关内存：网关重启即全员下线，符合“每次会话均需登录”。
- 登录失败达到 `maxLoginAttempts` 次后，该 IP 被锁定 `lockoutSeconds` 秒。

## 安全说明

- **远程访问请使用 HTTPS**：Harness 前端调用 `crypto.randomUUID()`，浏览器只在安全上下文（HTTPS 或 localhost）提供该 API——通过 `http://局域网IP:8080` 访问会报 `crypto.randomUUID is not a function`。为网关启用 TLS 即可解决：
  ```bash
  dsh-web-auth gen-cert --enable   # 生成自签名证书（SAN 自动含 localhost + 全部局域网 IP）并写入配置档
  # 重启 dsh web，然后访问 https://<主机IP>:8443（首次需在浏览器信任自签名证书）
  ```
  证书生成是纯 Node 实现（无需安装 openssl）。证书保存在 `~/.dsh/web-auth-cert.pem` / `web-auth-key.pem`（默认有效期 10 年）；可用 `--host <域名或IP>` 追加 SAN，`--days <n>` 调整有效期。HTTP 端口（默认 8080）仍会保留，仅适合本机/受信内网使用。
- 如需强制 HTTPS-only：把 `port` 设为 `0`（关闭 HTTP 监听）并加 `cookieSecure: true`。
- 配置文件权限建议 `600`（CLI 创建时自动设置）。
- Harness 本体请勿改为 `0.0.0.0` 绑定；所有远程访问都应经过本网关。
- **信任域（可选加固）**：默认 `trustedDomains: ["*"]` 接受任意域名；限制为具体域名后，网关只服务受信任的 `Host`/`Origin`（不匹配即 403，WebSocket 同样拒绝），可防 **DNS 重绑定**和意外的主机名暴露。规则支持精确主机名、`host:port`、`*.suffix` 通配、IPv6（如 `::1` 或带端口 `[::1]:8443`）。`Host` 是主闸门；`Origin: null`（沙箱 iframe/预览等不透明源）或缺失/无法解析的 Origin 不会被单独拒绝。**不要**只信任内网 IP——远程访问请把你实际使用的域名/IP 加进去（例：`["myhost.example.com", "*.corp.example"]`），通过 IPv6 环回访问时记得加 `::1`，改配置文件后重启生效。

## 设置管理（齿轮菜单）

本插件**完全不涉及官方设置入口**：不注册任何 settings 命名空间、不向 Harness 设置存储写入任何内容、客户端也不依赖设置 UI 模块——官方 `设置` 页面的行为与未安装本插件时完全一致。所有配置都落在本插件自己的 `~/.dsh/web-auth.yaml` 里（`users:` 账号列表 + `gateway:` 段保存 HTTPS 端口与信任域），通过网关自有端点读写。

设置入口是右下角齿轮浮窗（**仅在经网关访问时挂载**，页面带网关注入的 `__DSH_AUTH_GATEWAY__` 标记；直连 Harness 本机回环地址时不显示任何 UI）：

- **账号管理**：修改登录用户名与密码（密码为 write-only，留空 = 保持原密码）；`admin` 账号**必须保留**；
  - 每个账号可设置 `workDir`（工作目录限制）——该账号创建会话时会被强制落在该目录（`session.create` 的 `workspaceId` 会被替换为 `cwd=workDir`）；每次请求实时读取配置，改完立即生效；
  - 添加/删除账号请用"编辑配置文件（web-auth.yaml）"（CLI 只提供 `set-user` 修改当前账号）；
- **修改 HTTPS 端口**：保存后网关即时重新绑定，无需重启（保存在 `gateway.httpsPort`）；
- **信任域**：逗号分隔的受信任域名列表，默认 `*`（不限制）。保存后立即生效；限制后仅匹配的 `Host`/`Origin` 可访问网关（防 DNS 重绑定）。保存在 `gateway.trustedDomains`；
- **配置文件**：浮窗内"编辑配置文件（web-auth.yaml）"展开**网页内编辑器**——可直接修改并保存整个文件（保存前会校验 YAML 合法性、`users` 列表与 admin 账号存在性，校验失败不落盘；保存后立即对登录生效）。编辑器支持自动缩进：`Tab` 插入 2 空格，`Enter` 延续当前行缩进（行尾为 `:` 时再加 2 格）；
- **退出登录**：立即注销当前会话。

## 远程设置页修复（settings are unavailable in this browser）

Harness 的设置 UI 以浏览器侧的 `ctx.connection.isLoopback` 决定是否启用：远程地址（非回环）访问时，模型设置页会报 **"加载提供方目录失败: settings are unavailable in this browser"**。本插件通过两层机制修复：

1. 网关把每个经它代理的 HTML 页面都注入 `window.__DSH_AUTH_GATEWAY__` 标记——脚本插在 `<head>` 之后、早于 Harness 的任何引导脚本执行；
2. `scripts/patch-dsh-client.mjs` 对 Harness **实际下发**的 `@deepseek-ai/dsh-client-connection` 客户端包做幂等补丁，让 `isLoopback` 在该标记存在时也为 `true`（Harness 每次请求都从 node_modules 现读该包并以内容哈希做版本号，改完**刷新页面**即生效，无需重启）。设置页的 RPC 走网关注入的 `/api` 通道，`Host`/`Origin` 已被网关重写为回环地址，因此 Harness 的信任围栏正常放行。

```bash
npm run patch-client        # 手动应用/校验补丁（幂等；已打过则直接跳过）
npm run dev                 # 开发循环每次同步后自动重新应用
```

3. **运行时兜底（始终生效，无需写权限）**：本插件的客户端（`lib/client.js`）在带网关标记的页面里把共享 settings mirror 从 memory 模式**在线升级为 host 模式**（`settingsScope` 服务的 `mirror.persistence`），并立即发起一次 `settings.describe` 读取真实设置文档；同时把 `ctx.connection.isLoopback` 置为 `true`，使之后绑定的设置作用域同样走 host 持久化。这是纯浏览器端行为，随 `lib/client.js` 按请求实时下发，**任何环境都无需重启、无需修改 Harness 安装**（即使上面的补丁因权限/路径原因未能应用，设置页依然可用）。

注意：全局 `@deepseek-ai/dsh` 升级（`npm i -g`）会覆盖补丁，重新运行 `npm run patch-client` 即可；未打补丁时第 3 层（运行时升级）仍保证远程设置页可用。

## 远程产物文件下载

Harness 的“产物”文件芯片点击后调用 `host.openPath`——在**服务器本机**用原生应用打开文件，对远程浏览器毫无意义（无头服务器上还会失败）。经网关访问时，本插件把产物芯片的点击改为**下载到浏览器**：

1. **客户端**（`lib/client.js`）：在带网关标记的页面里拦截“产物”行文件芯片的点击（捕获阶段，先于对话自己的处理器），把芯片 `title` 里的绝对路径交给网关的下载端点；
2. **网关端点** `GET /dsh-gateway/download?path=<绝对路径>`（需登录）：以 `attachment` 响应流式返回文件内容。

安全边界：下载根为**该账号的 `workDir`（若配置）或服务器 home 目录**；路径先做 `realpath` 解析再校验必须落在下载根内（符号链接无法逃逸），目录、缺失文件、相对路径、越界路径分别以 4xx 拒绝。这是已登录账号的能力边界——与账号能创建会话、读取工作区文件的既有信任模型一致。

## 与其他插件的兼容性

- **dshmarket 的重启/备份/卸载**：dshmarket 的 `/dsh-market/restart`、`/dsh-market/backup`、`/dsh-market/self-uninstall` 拒绝任何带转发头（`forwarded`/`x-forwarded-for`/`x-real-ip`）的请求。网关代理这些路径时**不附加转发头**（Host/Origin 仍重写为回环，满足其同源校验），因此登录后可在市场里一键重启。注意：服务端代码在 Harness 启动时加载，**改过 `lib/` 服务端文件后需重启 Harness 才生效**（客户端 `client.js` 除外，按请求实时读取）。

## 配置项

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `host` | `0.0.0.0` | 网关绑定地址 |
| `httpEnabled` / `port` | `false` / `8080` | 明文 HTTP 监听（默认关闭，仅 HTTPS） |
| `httpsEnabled` / `httpsPort` | `false` / `8443` | 启用 HTTPS 监听（`httpsPort` 会被凭据文件 `gateway.httpsPort` 覆盖） |
| `httpsCertFile` / `httpsKeyFile` | `$DSH_HOME/web-auth-{cert,key}.pem` | TLS 证书/私钥 |
| `credentialsFile` | `$DSH_HOME/web-auth.yaml` | 账号密码配置文件（含 `gateway:` 设置段） |
| `trustedDomains` | `["*"]` | 信任域（Host/Origin 白名单）；`*` = 不限制，支持 `host`、`host:port`、`*.suffix`；被凭据文件 `gateway.trustedDomains` 覆盖 |
| `sessionTtlHours` | `24` | 登录有效时长（小时） |
| `cookiePersistent` | `false` | `false` = 浏览器会话级 Cookie（每次打开浏览器都要登录） |
| `cookieSecure` | `false` | 仅 HTTPS 使用时可开启 |
| `maxLoginAttempts` / `lockoutSeconds` | `5` / `600` | 登录失败节流 |
