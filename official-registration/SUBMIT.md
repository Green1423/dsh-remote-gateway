# Official list submission — awesome-dsh-plugin entry

This file is the PR payload for the official DSH plugin list
([awesome-dsh-plugin/awesome-dsh-plugin](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin)).
Per [contributing.md](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin/blob/main/contributing.md),
open a PR that adds exactly one file: `data/plugins/Green1423__dsh-remote-gateway.yml`
with this content:

```yaml
url: https://github.com/Green1423/dsh-remote-gateway
name: Green1423/dsh-remote-gateway
category: remote
description:
  en: 'Remote login gateway for the DeepSeek Harness web UI: username/password login, 24-hour sessions, HTTPS with auto-generated certificates, and an HTTP/WebSocket reverse proxy to the loopback server.'
  zh: 'DeepSeek Harness Web 界面远程登录网关：账号密码登录、24 小时会话、HTTPS 自动生成证书、HTTP/WebSocket 反向代理到回环服务。'
```

Then regenerate the two READMEs and commit them together:

```sh
npm ci
node scripts/generate-readme.mjs
```

## Checklist (all satisfied)

- [x] Repo declares a `dsh.bundle` manifest in `package.json` (installable via `dsh plugin add`)
- [x] Real, working code (login gateway + reverse proxy + remote produced-file download)
- [x] Repo older than 1 day with 10+ commits (CI-checked)
- [x] Actively maintained
- [ ] Add the `dsh-plugin` topic to the repo (Settings → Topics, or `gh repo edit --add-topic dsh-plugin`)
- [x] Description states only facts, no marketing

## Install command users will see

```sh
dsh plugin --profile web add github:Green1423/dsh-remote-gateway
```
