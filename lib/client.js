// dsh-remote-gateway — browser half. Renders a floating gear menu whose
// panel edits the gateway account (username + password; admin's username is
// editable), the HTTPS bind port and the trusted-domain list, hosts an
// in-page credentials-file editor (load / edit with auto-indent / save), and
// offers logout.
//
// The plugin has ZERO footprint in the harness's official settings system:
// it registers no settings namespace, depends on no settings UI module, and
// reads/writes its own configuration exclusively through the gateway's own
// endpoints (/dsh-gateway/config/settings, /dsh-gateway/config/credentials).
//
// The gear menu mounts ONLY when the page was reached through the login
// gateway (the page carries the gateway's injected __DSH_AUTH_GATEWAY__
// marker); direct non-gateway access to the harness web server shows
// nothing.
window.__ModuleLoader__.load({
	id: "dsh-remote-gateway",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
		let React = require("react");
		let runtime = require("@deepseek-ai/dsh-client-runtime/client");
		const createSnapshotStore = runtime.createSnapshotStore;

		const css = `
.dshAuth_menuBtn{position:fixed;right:16px;bottom:16px;z-index:2147483000;width:40px;height:40px;display:flex;align-items:center;justify-content:center;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);color:var(--dsw-alias-label-secondary);border-radius:50%;cursor:pointer;box-shadow:0 4px 16px rgba(0,0,0,.25);padding:0}
.dshAuth_menuBtn:hover{color:var(--dsw-alias-label-primary)}
.dshAuth_menuBtn svg{display:block}
.dshAuth_panel{position:fixed;right:16px;bottom:64px;z-index:2147483000;width:min(340px,calc(100vw - 28px));max-height:calc(100vh - 90px);overflow:auto;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);color:var(--dsw-alias-label-primary);border-radius:12px;padding:14px 16px;font:13px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;box-shadow:0 12px 40px rgba(0,0,0,.4)}
.dshAuth_title{font-size:15px;font-weight:600}
.dshAuth_desc{color:var(--dsw-alias-label-tertiary);margin:2px 0 10px;font-size:12px}
.dshAuth_field{margin:10px 0}
.dshAuth_label{display:block;margin-bottom:4px;color:var(--dsw-alias-label-secondary);font-size:12px}
.dshAuth_input{width:100%;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);color:var(--dsw-alias-label-primary);border-radius:8px;padding:6px 10px;font-size:13px;font-family:inherit}
.dshAuth_input:focus{outline:none;border-color:var(--dsw-alias-brand-primary)}
.dshAuth_error{color:var(--dsw-alias-label-error);font-size:12px;margin:8px 0;white-space:pre-wrap}
.dshAuth_hint{color:var(--dsw-alias-label-tertiary);font-size:12px;margin:4px 0}
.dshAuth_ok{color:var(--dsw-alias-label-secondary);font-size:12px;margin:8px 0}
.dshAuth_actions{display:flex;gap:8px;justify-content:flex-end;margin-top:12px}
.dshAuth_btn{appearance:none;font:inherit;cursor:pointer;border-radius:8px;padding:6px 14px;font-size:13px;border:1px solid transparent}
.dshAuth_btnPrimary{background:var(--dsw-alias-label-primary);color:var(--dsw-alias-bg-layer-3)}
.dshAuth_btnGhost{border-color:var(--dsw-alias-border-l2);color:var(--dsw-alias-label-secondary);background:transparent}
.dshAuth_btnDanger{border-color:var(--dsw-alias-border-l2);color:var(--dsw-alias-label-error);background:transparent}
.dshAuth_btn:disabled{opacity:.4;cursor:default}
.dshAuth_wide{width:100%;margin-top:12px}
.dshAuth_editorText{width:100%;box-sizing:border-box;min-height:220px;resize:vertical;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);border-radius:8px;padding:8px 10px;font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,"Courier New",monospace;tab-size:2;margin-top:8px}
.dshAuth_editorText:focus{outline:none;border-color:var(--dsw-alias-brand-primary)}
.dshAuth_producedFile{display:block;width:100%;box-sizing:border-box;text-align:left;margin:4px 0;padding:6px 10px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);border-radius:8px;font-size:12px;font-family:ui-monospace,SFMono-Regular,Consolas,"Courier New",monospace;cursor:pointer;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dshAuth_producedFile:hover{border-color:var(--dsw-alias-brand-primary);color:var(--dsw-alias-label-secondary)}
`;
		const cssTagId = "dsh-remote-gateway/client.css";
		if (typeof document !== "undefined" && document.querySelector("style[data-plugin-css=" + JSON.stringify(cssTagId) + "]") === null) {
			const tag = document.createElement("style");
			tag.dataset.plugin = "dsh-remote-gateway";
			tag.dataset.pluginCss = cssTagId;
			tag.textContent = css;
			document.head.appendChild(tag);
		}

		// No harness services are needed: everything goes through the gateway's
		// own endpoints (fetch), so the official settings system stays untouched.
		const inject = [];

		/** Tiny DOM builder. Accepts any number of children (elements, strings, arrays). */
		function h(tag, attrs, ...children) {
			const el = document.createElement(tag);
			if (attrs) for (const key of Object.keys(attrs)) {
				const value = attrs[key];
				if (key === "class") el.className = value;
				else if (key === "value") el.value = value;
				else if (key === "disabled") el.disabled = value;
				else if (key.startsWith("on")) el.addEventListener(key.slice(2).toLowerCase(), value);
				else if (key === "placeholder") el.placeholder = value;
				else if (key === "ariaLabel") el.setAttribute("aria-label", value);
				else el.setAttribute(key, value);
			}
			for (const child of children) {
				if (child === null || child === undefined) continue;
				const list = Array.isArray(child) ? child : [child];
				for (const item of list) {
					if (item === null || item === undefined) continue;
					el.appendChild(typeof item === "string" ? document.createTextNode(item) : item);
				}
			}
			return el;
		}

		/**
		 * Auto-indent for the config editor: Tab inserts 2 spaces, Enter opens
		 * a new line carrying the current line's indentation (2 more after a
		 * YAML map key ending in ":"). Returns the next value + cursor, or null
		 * when the key is not handled.
		 */
		function autoIndent(key, value, start, end) {
			let insert = null;
			if (key === "Tab") {
				insert = "  ";
			} else if (key === "Enter") {
				const lineStart = value.lastIndexOf("\n", start - 1) + 1;
				const line = value.slice(lineStart, start);
				let indent = /^[ \t]*/.exec(line)?.[0] ?? "";
				if (line.trimEnd().endsWith(":")) indent += "  ";
				insert = "\n" + indent;
			}
			if (insert === null) return null;
			return {
				next: value.slice(0, start) + insert + value.slice(end),
				cursor: start + insert.length,
			};
		}

		/**
		 * Form state for the gear menu, backed by the gateway's own settings
		 * endpoint (/dsh-gateway/config/settings) — NOT the harness settings
		 * service, so the official settings system is never involved.
		 */
		class GatewayController {
			constructor() {
				this.saving = false;
				this.failed = false;
				this.error = "";
				this.notice = "";
				this.status = "loading"; // loading | ready | unavailable
				this.loaded = false;
				this.loading = null;
				this.username = "";
				this.password = "";
				this.port = "8443";
				this.trustedDomains = "*";
				this.savedUsername = "";
				this.savedPort = "8443";
				this.savedTrustedDomains = "*";
				this.tick = 0; // bumped after each successful save (input re-seed)
				this.store = createSnapshotStore(this.projection());
			}
			dispose() {
				// nothing to tear down (no subscriptions)
			}
			projection() {
				return {
					status: this.status,
					writable: true,
					saving: this.saving,
					failed: this.failed,
					error: this.error,
					notice: this.notice,
					username: this.username,
					password: this.password,
					port: this.port,
					trustedDomains: this.trustedDomains,
					savedUsername: this.savedUsername,
					savedPort: this.savedPort,
					savedTrustedDomains: this.savedTrustedDomains,
					tick: this.tick,
					dirty: (this.username !== this.savedUsername)
						|| (this.password !== "")
						|| (this.port !== this.savedPort)
						|| (this.trustedDomains !== this.savedTrustedDomains),
				};
			}
			publish() {
				this.store.set(this.projection());
			}
			/** Load the form state once (idempotent; concurrent callers share one request). */
			ensureLoaded() {
				if (this.loaded) return Promise.resolve();
				if (this.loading !== null) return this.loading;
				this.status = "loading";
				this.publish();
				this.loading = (async () => {
					try {
						const res = await fetch("/dsh-gateway/config/settings");
						if (!res.ok) throw new Error("HTTP " + String(res.status));
						const doc = await res.json();
						const value = doc?.value;
						if (value && typeof value === "object") {
							this.username = typeof value.username === "string" ? value.username : "";
							this.port = String(typeof value.httpsPort === "number" ? value.httpsPort : 8443);
							this.trustedDomains = Array.isArray(value.trustedDomains) ? value.trustedDomains.join(", ") : "*";
							this.savedUsername = this.username;
							this.savedPort = this.port;
							this.savedTrustedDomains = this.trustedDomains;
						}
						this.loaded = true;
						this.status = "ready";
					} catch (err) {
						this.status = "unavailable";
						this.error = "设置加载失败：" + (err instanceof Error ? err.message : String(err));
					}
					this.publish();
				})();
				return this.loading;
			}
			editUsername(text) {
				this.username = text; // draft; no publish (avoids focus loss)
			}
			editPassword(text) {
				this.password = text; // draft; no publish
			}
			setPort(text) {
				this.port = text; // draft; no publish
			}
			setTrustedDomains(text) {
				this.trustedDomains = text; // draft; no publish
			}
			fail(message) {
				this.failed = true;
				this.error = message;
				this.publish();
			}
			async save() {
				if (this.saving) return;
				const username = String(this.username ?? "").trim();
				if (username === "") {
					this.fail("用户名不能为空");
					return;
				}
				const portNum = Number(String(this.port).trim());
				if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
					this.fail("端口必须是 1–65535 的整数");
					return;
				}
				// Trusted-domain rules: comma-separated, each without spaces or "/".
				const trustedDomains = String(this.trustedDomains ?? "").trim();
				const trustedList = trustedDomains === "" ? [] : trustedDomains.split(",").map((rule) => rule.trim()).filter((rule) => rule !== "");
				if (trustedList.length === 0) {
					this.fail("信任域不能为空（填 * 表示不限制）");
					return;
				}
				for (const rule of trustedList) {
					if (!/^[^\s/]+$/.test(rule)) {
						this.fail(`信任域 "${rule}" 格式无效（不能含空格或 /）`);
						return;
					}
				}
				this.saving = true;
				this.failed = false;
				this.error = "";
				this.notice = "";
				this.publish();
				try {
					const res = await fetch("/dsh-gateway/config/settings", {
						method: "PUT",
						headers: { "content-type": "application/json" },
						body: JSON.stringify({
							username,
							password: String(this.password ?? ""),
							httpsPort: portNum,
							trustedDomains: trustedList,
						}),
					});
					const doc = await res.json().catch(() => null);
					if (!res.ok || doc === null || doc.ok !== true) {
						this.failed = true;
						this.error = "保存失败：" + (doc?.error !== undefined && doc.error !== null ? String(doc.error) : "HTTP " + String(res.status));
					} else {
						this.password = "";
						const value = doc.value;
						if (value && typeof value === "object") {
							if (typeof value.username === "string") this.username = value.username;
							if (typeof value.httpsPort === "number") this.port = String(value.httpsPort);
							if (Array.isArray(value.trustedDomains)) this.trustedDomains = value.trustedDomains.join(", ");
						}
						this.savedUsername = this.username;
						this.savedPort = this.port;
						this.savedTrustedDomains = this.trustedDomains;
						this.tick += 1;
						this.notice = portNum === Number(this.port)
							? "已保存"
							: "已保存：端口已切换，请用新端口重新访问";
					}
				} catch (err) {
					this.failed = true;
					this.error = "保存失败：" + (err instanceof Error ? err.message : String(err));
				}
				this.saving = false;
				this.publish();
			}
			discard() {
				this.password = "";
				this.failed = false;
				this.error = "";
				this.notice = "";
				this.publish();
			}
			logout() {
				window.location.assign("/logout");
			}
		}

		/** Feather-style settings gear (stroke inherits currentColor). */
		const GEAR_SVG = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.09a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>';

		/**
		 * Floating gear button + settings panel (plain DOM). Two views:
		 * "form" (account/port/trusted domains + logout) and "editor" (config file).
		 */
		function mountGatewayMenu(controller) {
			if (typeof document === "undefined") return;
			const run = () => {
				if (document.getElementById("dsh-auth-menu-root") !== null) return;
				if (document.body === null) {
					setTimeout(run, 100);
					return;
				}
				const root = document.createElement("div");
				root.id = "dsh-auth-menu-root";
				document.body.appendChild(root);

				let open = false;
				let view = "form"; // "form" | "editor"
				let configLoaded = false;
				let configSaving = false;
				const button = h("button", {
					class: "dshAuth_menuBtn",
					type: "button",
					title: "登录网关设置",
					ariaLabel: "登录网关设置",
					onClick: (event) => {
						event.stopPropagation();
						toggle();
					},
				});
				button.innerHTML = GEAR_SVG;
				const panel = h("div", { class: "dshAuth_panel", hidden: true });

				// ── form view ──────────────────────────────────────────────
				const statusEl = h("p", { class: "dshAuth_hint" });
				const formView = h("div", { class: "dshAuth_formView" },
					h("div", { class: "dshAuth_title" }, "登录网关"),
					h("div", { class: "dshAuth_desc" }, "修改登录用户名与密码（保存后立即生效）"),
					statusEl,
					h("div", { class: "dshAuth_field" },
						h("label", { class: "dshAuth_label" }, "用户名"),
						h("input", {
							class: "dshAuth_input dshAuth_nameInput", type: "text", placeholder: "用户名",
							onInput: (e) => controller.editUsername(e.target.value),
						}),
					),
					h("div", { class: "dshAuth_field" },
						h("label", { class: "dshAuth_label" }, "密码"),
						h("input", {
							class: "dshAuth_input dshAuth_pwInput", type: "password", placeholder: "留空保持不变",
							onInput: (e) => controller.editPassword(e.target.value),
						}),
					),
					h("div", { class: "dshAuth_field" },
						h("label", { class: "dshAuth_label" }, "HTTPS 端口"),
						h("input", {
							class: "dshAuth_input dshAuth_portInput", type: "number", min: 1, max: 65535,
							onInput: (e) => controller.setPort(e.target.value),
						}),
						h("p", { class: "dshAuth_hint" }, "保存后网关立即切换到新端口，当前连接会断开，请用新端口重新访问。"),
					),
					h("div", { class: "dshAuth_field" },
						h("label", { class: "dshAuth_label" }, "信任域"),
						h("input", {
							class: "dshAuth_input dshAuth_trustedInput", type: "text", placeholder: "*",
							onInput: (e) => controller.setTrustedDomains(e.target.value),
						}),
						h("p", { class: "dshAuth_hint" }, "逗号分隔；* = 允许任意域名（默认）。限制后仅受信任的 Host/Origin 可访问（防 DNS 重绑定）。"),
					),
					h("p", { class: "dshAuth_error", hidden: true }),
					h("p", { class: "dshAuth_ok", hidden: true }),
					h("button", {
						class: "dshAuth_btn dshAuth_btnGhost dshAuth_wide dshAuth_editConfig",
						type: "button",
						onClick: () => openEditor(),
					}, "编辑配置文件（web-auth.yaml）"),
					h("div", { class: "dshAuth_actions" },
						h("button", { class: "dshAuth_btn dshAuth_btnDanger dshAuth_logout", type: "button", onClick: () => controller.logout() }, "退出登录"),
						h("button", { class: "dshAuth_btn dshAuth_btnGhost dshAuth_reset", type: "button", onClick: () => controller.discard() }, "重置"),
						h("button", { class: "dshAuth_btn dshAuth_btnPrimary dshAuth_save", type: "button", onClick: () => controller.save() }, "保存"),
					),
				);

				const renderForm = () => {
					const state = controller.store.getSnapshot();
					const busy = state.status !== "ready" || !state.writable || state.saving;
					if (state.status !== "ready") {
						statusEl.textContent = state.status === "unavailable" ? "设置当前不可用" : "加载中…";
					} else {
						statusEl.textContent = "";
					}
					const nameInput = formView.querySelector(".dshAuth_nameInput");
					if (nameInput !== null && nameInput !== document.activeElement) nameInput.value = state.username;
					const pwInput = formView.querySelector(".dshAuth_pwInput");
					if (pwInput !== null && pwInput !== document.activeElement) pwInput.value = state.password;
					const portInput = formView.querySelector(".dshAuth_portInput");
					if (portInput !== null && portInput !== document.activeElement) portInput.value = state.port;
					const trustedInput = formView.querySelector(".dshAuth_trustedInput");
					if (trustedInput !== null && trustedInput !== document.activeElement) trustedInput.value = state.trustedDomains;
					const errEl = formView.querySelector(".dshAuth_error");
					errEl.textContent = state.error;
					errEl.hidden = state.error === "";
					const okEl = formView.querySelector(".dshAuth_ok");
					okEl.textContent = state.notice;
					okEl.hidden = state.notice === "";
					const saveBtn = formView.querySelector(".dshAuth_save");
					saveBtn.disabled = busy;
					saveBtn.textContent = state.saving ? "保存中…" : "保存";
					const resetBtn = formView.querySelector(".dshAuth_reset");
					resetBtn.disabled = busy;
					const logoutBtn = formView.querySelector(".dshAuth_logout");
					logoutBtn.disabled = busy;
					const editBtn = formView.querySelector(".dshAuth_editConfig");
					editBtn.disabled = busy;
					for (const input of formView.querySelectorAll(".dshAuth_input")) input.disabled = busy;
				};

				// ── editor view ────────────────────────────────────────────
				const editorStatus = h("p", { class: "dshAuth_hint", hidden: true });
				const editorText = h("textarea", {
					class: "dshAuth_editorText",
					rows: 16,
					spellCheck: "false",
				});
				const editorSaveBtn = h("button", { class: "dshAuth_btn dshAuth_btnPrimary", type: "button" }, "保存配置文件");
				const editorBackBtn = h("button", { class: "dshAuth_btn dshAuth_btnGhost", type: "button" }, "返回");
				const editorView = h("div", { class: "dshAuth_editorView", hidden: true },
					h("div", { class: "dshAuth_title" }, "配置文件（web-auth.yaml）"),
					h("div", { class: "dshAuth_desc" }, "保存前校验 YAML 合法性；保存后立即生效。Tab 缩进，Enter 自动续行。"),
					editorStatus,
					editorText,
					h("div", { class: "dshAuth_actions" },
						editorBackBtn,
						editorSaveBtn,
					),
				);

				const editorSetStatus = (text, kind) => {
					editorStatus.textContent = text;
					editorStatus.hidden = text === "";
					editorStatus.className = kind === "error" ? "dshAuth_error" : kind === "ok" ? "dshAuth_ok" : "dshAuth_hint";
				};
				const loadConfig = async () => {
					editorSetStatus("加载中…", "hint");
					try {
						const res = await fetch("/dsh-gateway/config/credentials");
						if (!res.ok) throw new Error("HTTP " + String(res.status));
						editorText.value = await res.text();
						configLoaded = true;
						editorSetStatus("", "hint");
					} catch (err) {
						editorSetStatus("加载失败：" + (err instanceof Error ? err.message : String(err)), "error");
					}
				};
				const saveConfig = async () => {
					if (configSaving) return;
					configSaving = true;
					editorSaveBtn.disabled = true;
					editorSaveBtn.textContent = "保存中…";
					editorSetStatus("", "hint");
					try {
						const res = await fetch("/dsh-gateway/config/credentials", {
							method: "PUT",
							headers: { "content-type": "text/plain; charset=utf-8" },
							body: editorText.value,
						});
						const doc = await res.json().catch(() => null);
						if (!res.ok) {
							editorSetStatus("保存失败：" + (doc?.error !== undefined && doc.error !== null ? String(doc.error) : "HTTP " + String(res.status)), "error");
						} else {
							editorSetStatus("配置文件已保存，登录立即生效", "ok");
						}
					} catch (err) {
						editorSetStatus("保存失败：" + (err instanceof Error ? err.message : String(err)), "error");
					}
					configSaving = false;
					editorSaveBtn.disabled = false;
					editorSaveBtn.textContent = "保存配置文件";
				};
				editorText.addEventListener("keydown", (e) => {
					const result = autoIndent(e.key, editorText.value, editorText.selectionStart, editorText.selectionEnd);
					if (result !== null) {
						e.preventDefault();
						editorText.value = result.next;
						editorText.setSelectionRange(result.cursor, result.cursor);
					}
				});
				editorSaveBtn.addEventListener("click", () => saveConfig());
				editorBackBtn.addEventListener("click", () => setView("form"));

				const setView = (next) => {
					view = next;
					formView.hidden = next !== "form";
					editorView.hidden = next !== "editor";
					if (next === "form") editorSetStatus("", "hint");
					if (next === "editor" && !configLoaded) loadConfig();
				};

				panel.appendChild(formView);
				panel.appendChild(editorView);

				const toggle = (force) => {
					open = force !== undefined ? force : !open;
					panel.hidden = !open;
					if (open) {
						controller.ensureLoaded();
						if (view === "form") renderForm();
						else if (view === "editor" && !configLoaded) loadConfig();
					}
				};
				const openEditor = () => setView("editor");

				root.appendChild(button);
				root.appendChild(panel);
				controller.store.subscribe(() => { if (open && view === "form") renderForm(); });
				document.addEventListener("click", (event) => {
					if (open && !root.contains(event.target)) toggle(false);
				});
				document.addEventListener("keydown", (event) => {
					if (event.key === "Escape" && open) toggle(false);
				});
			};
			run();
		}

		/**
		 * Remote sessions behind the gateway: the harness browser half derives
		 * ctx.connection.isLoopback from the page hostname alone, so a remote
		 * page looks non-loopback and the shared settings mirror is built in
		 * memory mode — the Models provider directory and other settings
		 * surfaces then fail with "settings are unavailable in this browser",
		 * even though the gateway authenticated the request and its loopbacked
		 * Host/Origin rewrite makes the settings RPCs reach the harness. This
		 * upgrades the LIVE mirror to host mode (the browser then reads the
		 * real settings document) and flags the connection as loopback so
		 * later settings-scope binds pick host persistence too. Client-only:
		 * it takes effect on the next page load — no server restart needed.
		 * @param ctx - client cordis context.
		 */
		function upgradeRemoteSettings(ctx) {
			const attempt = (attemptsLeft) => {
				try {
					const scope = ctx.get("settingsScope");
					const mirror = scope !== null && typeof scope === "object" ? scope.mirror : undefined;
					if (mirror === undefined || mirror === null) {
						// settingsScope not provided yet — retry briefly.
						if (attemptsLeft > 0) return setTimeout(() => attempt(attemptsLeft - 1), 300);
					} else if (mirror.persistence === "memory") {
						mirror.persistence = "host";
						mirror.load().catch(() => { /* describe failure surfaces in the settings UI itself */ });
					}
				} catch {
					if (attemptsLeft > 0) return setTimeout(() => attempt(attemptsLeft - 1), 300);
				}
				try {
					const connection = ctx.get("connection");
					if (connection !== null && typeof connection === "object" && connection.isLoopback === false) {
						connection.isLoopback = true;
					}
				} catch { /* connection unavailable — the mirror upgrade already covers the provider directory */ }
			};
			attempt(5);
		}

		/**
		 * Download one produced file through the gateway endpoint. The path is
		 * validated server-side against the account's download root (workDir
		 * or home); failures return false so callers can fall back.
		 * @param path - absolute server path of the produced file.
		 * @param doFetch - the fetch implementation to use (avoids recursion
		 *   when called from the openPath fetch interceptor).
		 * @returns whether the file was downloaded.
		 */
		async function downloadProducedFile(path, doFetch = fetch) {
			try {
				const response = await doFetch("/dsh-gateway/download?path=" + encodeURIComponent(path));
				if (!response.ok) return false;
				const blob = await response.blob();
				const url = URL.createObjectURL(blob);
				const anchor = document.createElement("a");
				anchor.href = url;
				anchor.download = path.split(/[\\/]/).pop() ?? "download";
				document.body.appendChild(anchor);
				anchor.click();
				anchor.remove();
				setTimeout(() => URL.revokeObjectURL(url), 60_000);
				return true;
			} catch (err) {
				console.error("[web-auth] 产物下载失败：" + (err instanceof Error ? err.message : String(err)));
				return false;
			}
		}

		/**
		 * Remote produced-file download. The harness "产物" chips and the
		 * in-message file mentions call host.openPath, which opens the file
		 * natively ON THE SERVER — meaningless for a remote browser (and
		 * unavailable on headless hosts). When the page was reached through
		 * the gateway this mounts three layers:
		 *   1. chip clicks are intercepted (capture phase) and downloaded;
		 *   2. the "+N 个文件" fold counter opens a produced-file panel that
		 *      lists EVERY produced path of the current session (pulled from
		 *      sessions.history views) — the fold never hides a file from
		 *      download;
		 *   3. window.fetch is patched for POST /api/host.openPath so every
		 *      other open entry (file mentions, any future caller) downloads
		 *      instead of failing on the server's xdg-open.
		 * @param ctx - client cordis context (sessions/connection services).
		 */
		function mountProducedFiles(ctx) {
			if (typeof document === "undefined") return;

			// 1. produced chips → download directly.
			document.addEventListener("click", (event) => {
				const target = event.target;
				if (target === null || typeof target.closest !== "function") return;
				const chip = target.closest("[data-produced-files-row] button[title]");
				if (chip === null || chip === undefined) return;
				const path = chip.getAttribute("title") ?? "";
				if (path === "" || !path.startsWith("/")) return;
				event.preventDefault();
				event.stopPropagation();
				downloadProducedFile(path);
			}, true);

			// 2. fold counter ("+N 个文件") → produced-file panel with the
			//    full session list.
			const openProducedPanel = async () => {
				const paths = [];
				try {
					const sessions = ctx.get("sessions");
					const current = sessions !== null && sessions !== undefined && sessions.list !== undefined
						? sessions.list.getSnapshot().current
						: undefined;
					const api = ctx.get("connection")?.api;
					if (typeof current === "string" && current !== "" && api !== undefined && api !== null) {
						let beforeSeq = undefined;
						for (let page = 0; page < 3; page++) {
							const { result } = await api.sessions.history({
								sessionId: current,
								...(beforeSeq === undefined ? {} : { beforeSeq }),
								maxMessages: 100,
							});
							if (!result.ok) break;
							const events = result.value.events;
							for (const entry of events) {
								// History views are wrapped as {for, view}; the inner
								// view carries the card/locations shape produced
								// paths are derived from.
								const wrapped = entry !== null && typeof entry === "object" ? entry.view : undefined;
								if (wrapped === null || typeof wrapped !== "object") continue;
								const view = wrapped.view !== null && typeof wrapped.view === "object" ? wrapped.view : wrapped;
								if (view.card !== "diff" && !(view.card === "generic" && view.kind === "edit")) continue;
								for (const location of view.locations ?? []) {
									const produced = location !== null && typeof location === "object" ? location.path : undefined;
									if (typeof produced === "string" && produced.startsWith("/") && !paths.includes(produced)) paths.push(produced);
								}
							}
							if (result.value.hasMore !== true || events.length === 0 || paths.length > 0) break;
							beforeSeq = events[events.length - 1]?.event?.seq;
							if (typeof beforeSeq !== "number") break;
						}
					}
				} catch { /* history unavailable — panel renders with what we have */ }
				renderProducedPanel(paths);
			};
			document.addEventListener("click", (event) => {
				const target = event.target;
				if (target === null || typeof target.closest !== "function") return;
				const more = target.closest("[data-produced-files-row] span");
				if (more === null || more === undefined) return;
				event.preventDefault();
				event.stopPropagation();
				openProducedPanel();
			}, true);

			// 3. openPath RPC → download (covers file mentions and any other
			//    open entry). A refused download falls through to the real RPC.
			if (typeof window !== "undefined" && typeof window.fetch === "function") {
				const originalFetch = window.fetch.bind(window);
				window.fetch = async (input, init) => {
					const method = (init !== undefined && init !== null && typeof init.method === "string" ? init.method : undefined)
						?? (typeof Request !== "undefined" && input instanceof Request ? input.method : "GET");
					const rawUrl = typeof input === "string" ? input : input instanceof URL ? input.href : input?.url;
					const pathOnly = typeof rawUrl === "string" ? String(rawUrl).split("?")[0] : "";
					if (method === "POST" && (pathOnly === "/api/host.openPath" || pathOnly.endsWith("/api/host.openPath"))) {
						let payload = null;
						try { payload = JSON.parse(String(init?.body ?? "")); } catch { payload = null; }
						const target = payload !== null && typeof payload === "object" && payload.payload !== null && typeof payload.payload === "object"
							? payload.payload.path
							: undefined;
						if (typeof target === "string" && target.startsWith("/") && await downloadProducedFile(target, originalFetch)) {
							const rpcId = typeof payload.rpcId === "string" ? payload.rpcId : "openPath-downloaded";
							return new Response(JSON.stringify({
								type: "server-response",
								rpcId,
								result: { ok: true, value: { opened: true } },
							}), { status: 200, headers: { "content-type": "application/json" } });
						}
					}
					return originalFetch(input, init);
				};
			}
		}

		/** Rendered produced-file panel (plain DOM, mirrors the gear-menu styling). */
		function renderProducedPanel(paths) {
			if (document.getElementById("dsh-auth-produced-root") !== null) return;
			const root = document.createElement("div");
			root.id = "dsh-auth-produced-root";
			const panel = h("div", { class: "dshAuth_panel", style: "bottom:110px" },
				h("div", { class: "dshAuth_title" }, "会话产物"),
				h("div", { class: "dshAuth_desc" }, paths.length === 0 ? "未找到产物文件" : "点击文件即可下载（共 " + String(paths.length) + " 个）"),
				...paths.map((path) => h("button", {
					class: "dshAuth_producedFile",
					type: "button",
					title: path,
					onClick: () => downloadProducedFile(path),
				}, path.split(/[\\/]/).pop() ?? path)),
				h("div", { class: "dshAuth_actions" },
					h("button", { class: "dshAuth_btn dshAuth_btnGhost", type: "button", onClick: () => { root.remove(); } }, "关闭"),
				),
			);
			root.appendChild(panel);
			document.body.appendChild(root);
			document.addEventListener("keydown", (event) => {
				if (event.key === "Escape" && document.getElementById("dsh-auth-produced-root") !== null) {
					root.remove();
				}
			}, { once: true });
		}

		function apply(ctx) {
			const controller = new GatewayController();
			ctx.effect(() => () => controller.dispose(), "dsh-remote-gateway: controller");
			// The gear menu only makes sense behind the login gateway: the
			// gateway injects the __DSH_AUTH_GATEWAY__ trust marker into every
			// HTML page it proxies, so its presence means this page was reached
			// through the gateway. Direct (non-gateway) access to the harness
			// web server hides the floating menu.
			if (typeof window !== "undefined" && window.__DSH_AUTH_GATEWAY__ === true) {
				upgradeRemoteSettings(ctx);
				mountProducedFiles(ctx);
				mountGatewayMenu(controller);
			}
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
