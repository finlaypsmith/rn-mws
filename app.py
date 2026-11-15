#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import sys
import subprocess
import base64
import urllib.parse
from datetime import datetime, timezone, timedelta
from curl_cffi import requests

# 本地测试时从脚本同目录加载 .env（CI 中用 secrets 注入，优先级高于 .env）
def load_env(path=None):
    env_path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())

load_env()

# ================= 环境变量配置(可私库直接填写在双引号里) =================
EMAIL         = os.environ.get("EMAIL") or ""           # 邮箱仅通知使用，可随意填写
SERVER_IDS    = os.environ.get("SERVER_IDS") or ""      # server id，多个用逗号分隔
COOKIE        = os.environ.get("COOKIE") or ""          # __Host-mrtcloud_token 的值，有效期约1个月，失效后自动用 Discord 登录刷新
DISCORD_TOKEN = os.environ.get("DISCORD_TOKEN") or ""   # Discord Token，COOKIE 失效时用它自动重新登录
GH_TOKEN      = os.environ.get("GH_TOKEN") or ""        # GitHub PAT，用于把新 COOKIE 写回仓库 Secrets（留空则跳过写入）
TG_CHAT_ID    = os.environ.get("TG_CHAT_ID") or ""      # TG 通知，可选
TG_BOT_TOKEN  = os.environ.get("TG_BOT_TOKEN") or ""    # TG 通知，可选

# ------------- 代理配置 -------------
IS_PROXY     = os.environ.get("IS_PROXY", "false").lower() == "true"   # 是否启用代理, 节点配置NODE_LINK节点自动开启
PROXY_SERVER = os.environ.get("PROXY_SERVER", "").strip() or "http://127.0.0.1:1081"
HEADLESS     = os.environ.get("HEADLESS", "false").lower() == "true"   # 浏览器无头模式(CI 用 xvfb-run 有头过盾更稳)

# ------------- MWS 站点 / Discord OAuth 配置 -------------
SITE_ORIGIN = "https://cloud.m-ws.cc"          # 控制台前端（续期 API 入口）
API_ORIGIN  = "https://cloud-api.m-ws.cc"      # 后端 auth 所在域
COOKIE_NAME = "__Host-mrtcloud_token"
DISCORD_CLIENT_ID     = "1508034084377464903"
OAUTH_REDIRECT_URI    = f"{API_ORIGIN}/auth/callback"
OAUTH_SCOPE           = "identify"
DISCORD_AUTHORIZE_API = "https://discord.com/api/v9/oauth2/authorize"
DISCORD_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)

# ==========================================
def normalize_proxy_url(value: str) -> str:
    """socks5:// 是「本地解析域名」：curl_cffi 解析时优先选 AAAA(IPv6)，
    而代理节点普遍只有 IPv4 出口，IPv6 地址送进隧道会被立刻断开，
    表现为 curl: (35) BoringSSL SSL_connect: Connection closed abruptly。
    统一改写成 socks5h://，让代理端解析域名，顺带绕开本地 DNS 污染。"""
    if value.lower().startswith("socks5://"):
        return "socks5h://" + value[len("socks5://"):]
    return value

def build_proxies():
    """按配置返回 curl_cffi 需要的代理字典，未启用则返回 None"""
    if IS_PROXY:
        server = normalize_proxy_url(PROXY_SERVER)
        return {"http": server, "https": server}
    return None

# 获取出口IP及其时区 (api.ip.sb/geoip, 失败时降级到 ip-api.com)
def get_egress_info(proxy_server: str = ""):
    proxies = None
    if proxy_server:
        proxies = build_proxies()
    headers = {"User-Agent": DISCORD_UA}
    for url, pick in (
        ("https://api.ip.sb/geoip", lambda d: (d.get("ip"), d.get("timezone"))),
        ("http://ip-api.com/json/?fields=query,timezone", lambda d: (d.get("query"), d.get("timezone"))),
    ):
        try:
            data = requests.get(url, proxies=proxies, headers=headers, timeout=15, impersonate="chrome136").json()
            ip, tz = pick(data)
            if ip:
                return ip, tz
        except Exception as e:
            print(f"⚠️ 获取出口信息失败 ({url}): {e}")
    return None, None

def send_tg_notification(message: str):
    """发送 Telegram 通知"""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("⚠️ 未配置 TG_BOT_TOKEN 或 TG_CHAT_ID，跳过 TG 通知。")
        return

    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TG_CHAT_ID, "text": message, "parse_mode": "HTML"}

    try:
        resp = requests.post(
            url, json=payload, timeout=10, impersonate="chrome136", proxies=build_proxies()
        )
        if resp.status_code == 200:
            print("✅ TG 通知发送成功")
        else:
            print(f"❌ TG 通知发送失败: {resp.text}")
    except Exception as e:
        print(f"❌ TG 通知发送异常: {e}")

def mask_secret(value: str) -> str:
    if not value:
        return "***"
    return value[:4] + "..." + value[-4:] if len(value) > 8 else "***"

def update_github_secret(secret_name: str, new_value: str) -> bool:
    """调用 gh cli 更新仓库 Secrets；未配置 GH_TOKEN 时直接跳过"""
    if not new_value:
        print(f"⚠️ 跳过更新 {secret_name}：新值为空")
        return False
    if not GH_TOKEN:
        print(f"ℹ️ 未配置 GH_TOKEN，跳过写入 {secret_name}（新值: {mask_secret(new_value)}）")
        return False

    print(f"🔄 更新 Secret: {secret_name} (新值: {mask_secret(new_value)})")
    try:
        env = os.environ.copy()
        env["GH_TOKEN"] = GH_TOKEN
        proc = subprocess.run(
            ["gh", "secret", "set", secret_name, "--body", new_value],
            capture_output=True, text=True, timeout=30, check=False, env=env,
        )
        if proc.returncode == 0:
            print(f"✅ Secret {secret_name} 更新成功")
            return True
        print(f"❌ 更新 Secret {secret_name} 失败: {proc.stderr.strip()}")
        return False
    except Exception as e:
        print(f"❌ 更新 Secret {secret_name} 异常: {e}")
        return False

def login_headers():
    """带 COOKIE 的 API 请求头"""
    return {
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8,en;q=0.7",
        "Content-Type": "application/json",
        "Cookie": f"{COOKIE_NAME}={COOKIE}",
        "Origin": SITE_ORIGIN,
        "Referer": f"{SITE_ORIGIN}/",
    }

def get_expiry_from_cookie(value: str):
    """从 JWT 里解析过期时间（JST 展示），解析失败返回 None"""
    try:
        payload_b64 = value.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = payload.get("exp")
        if not exp:
            return None
        # 站点是日本服务，按 JST (UTC+9) 展示
        return datetime.fromtimestamp(exp, tz=timezone.utc).astimezone(
            timezone(timedelta(hours=9))
        )
    except Exception:
        return None

def renew_server(server_id: str):
    """调用续期 API，返回 (是否成功, HTTP 状态码, 剩余小时数)"""
    url = f"{SITE_ORIGIN}/api/bots/{server_id}/renew"

    try:
        response = requests.post(
            url,
            headers=login_headers(),
            timeout=15,
            impersonate="chrome136",
            proxies=build_proxies(),
        )

        if response.status_code == 200:
            try:
                remaining_hours = response.json().get("timer", {}).get("remaining_hours", "未知")
            except json.JSONDecodeError:
                remaining_hours = "未知"

            print(f"✅ 服务器 [{server_id}] 续期成功，剩余 {remaining_hours} 小时")
            return True, response.status_code, remaining_hours

        print(f"❌ 服务器 [{server_id}] 续期失败，状态码: {response.status_code}, 响应: {response.text[:300]}")
        return False, response.status_code, None

    except Exception as e:
        print(f"❌ 服务器 [{server_id}] 请求发生异常, 请检查服务器是否被删除: {e}")
        return False, None, None

# ================= Discord OAuth 登录（API 请求失败时的兜底，纯 HTTP） =================
#   1) GET /auth/login 拿授权 URL（含 state），Session 自动种下 oauth_state cookie
#   2) DISCORD_TOKEN 调 Discord OAuth2 API 授权，拿回带 code 的回调 location
#   3) GET 回调 -> 302 到 /auth/success?code=<一次性code>
#   4) POST /api/auth/exchange 用一次性 code 换取新 __Host-mrtcloud_token

STATE_RE = re.compile(r"[?&]state=([^&]+)")

def discord_authorize(state: str) -> str:
    """用 DISCORD_TOKEN 请求 Discord OAuth2 API 授权，返回带 code 的回调 location"""
    query = urllib.parse.urlencode({
        "client_id":     DISCORD_CLIENT_ID,
        "redirect_uri":  OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope":         OAUTH_SCOPE,
        "state":         state,
    })
    authorize_url = f"{DISCORD_AUTHORIZE_API}?{query}"
    referer = f"https://discord.com/oauth2/authorize?{query}"

    headers = {
        "accept":           "*/*",
        "authorization":    DISCORD_TOKEN,
        "content-type":     "application/json",
        "origin":           "https://discord.com",
        "referer":          referer,
        "user-agent":       DISCORD_UA,
        "x-discord-locale": "ja",
        "x-super-properties": base64.b64encode(json.dumps({
            "os": "Windows",
            "browser": "Chrome",
            "device": "",
            "system_locale": "ja-JP",
            "browser_version": "140.0.0.0",
            "os_version": "10",
        }).encode()).decode(),
    }

    body = json.dumps({
        "permissions": "0",
        "authorize": True,
        "integration_type": 0,
        "location_context": {
            "guild_id": "10000",
            "channel_id": "10000",
            "channel_type": 10000,
        },
    })

    data = None

    # 途径1：curl_cffi 直连（CI/有代理环境通常可用）
    try:
        resp = requests.post(
            authorize_url,
            headers=headers,
            data=body,
            timeout=12,
            impersonate="chrome136",
            proxies=build_proxies(),
        )
        if resp.status_code == 200:
            data = resp.json()
        else:
            print(f"⚠️ Discord OAuth2 直连返回 HTTP {resp.status_code} - {resp.text[:200]}")
    except Exception as e:
        print(f"⚠️ Discord OAuth2 直连失败: {e}")

    if not data:
        print("❌ Discord OAuth2 授权失败，请检查 DISCORD_TOKEN 或网络")
        return ""

    location = data.get("location", "")
    if not location:
        print(f"❌ 授权响应没有 location 字段: {data}")
        return ""

    print(f"✅ 拿到回调 URL: {re.sub(r'code=[^&]+', 'code=***', location)}")
    return location

def fetch_new_cookie_via_http() -> str:
    """纯 HTTP 完成 Discord OAuth 授权拿cookie：
    1) GET /auth/login 拿 302 -> discord 授权页 URL（含 state），Session 自动种下 oauth_state cookie
    2) DISCORD_TOKEN 调 Discord OAuth2 API 授权 -> 带 code 的回调 location
    3) GET 回调 -> 302 到 /auth/success?code=<一次性code>（Session 自动带 state cookie）
    4) POST /api/auth/exchange 用一次性 code 换取新 __Host-mrtcloud_token
    curl_cffi 的 chrome TLS 指纹真实，不会被 Cloudflare 掐断。"""
    if not DISCORD_TOKEN:
        print("❌ 未配置 DISCORD_TOKEN，无法自动重新登录")
        return ""

    print("\n🔑 COOKIE 续期失败，切换到Discord OAuth登录获取新的Cookie...")

    try:
        sess = requests.Session(impersonate="chrome136")
        if IS_PROXY:
            sess.proxies = build_proxies()

        # 1) 触发 /auth/login，取授权 URL（含后端种下的 state）
        resp = sess.get(f"{API_ORIGIN}/auth/login", timeout=20, allow_redirects=False)
        authorize_page = resp.headers.get("location", "")
        if resp.status_code != 302 or not authorize_page:
            print(f"❌ /auth/login 未返回授权跳转: HTTP {resp.status_code} {resp.text[:150]}")
            return ""
        print(f"✅ 拿到 Discord 授权入口: {re.sub(r'state=[^&]+', 'state=***', authorize_page)}")

        m = STATE_RE.search(authorize_page) or STATE_RE.search(urllib.parse.unquote(authorize_page))
        if not m:
            print("❌ 授权 URL 中未找到 state")
            return ""
        state = urllib.parse.unquote(m.group(1))

        # 2) Discord 侧授权（带 DISCORD_TOKEN 的 API 调用）
        location = discord_authorize(state)
        if not location:
            return ""

        # 3) 打开回调，Session 会自动带上 oauth_state cookie。
        #    成功时后端 302 到 cloud.m-ws.cc/auth/success?code=<一次性code>（不直接发 token）
        print("↩️ 携带授权码请求回调...")
        cb = sess.get(location, timeout=20, allow_redirects=False)
        # print(f"↩️ 回调响应: HTTP {cb.status_code}")

        success_code = ""
        if cb.status_code == 302:
            loc = cb.headers.get("location", "")
            if "/auth/success" in loc:
                mm = re.search(r"[?&]code=([^&]+)", loc)
                if mm:
                    success_code = urllib.parse.unquote(mm.group(1))
            else:
                print(f"   回调跳转到: {loc[:120]}")
        else:
            print(f"   回调返回异常状态: {cb.text[:150]}")

        if not success_code:
            print("❌ 回调未返回 auth/success 换取码（可能 state 校验失败或 code 无效）")
            return ""

        # 4) 模拟前端 auth/success 页面：用一次性 code 调 exchange 换真正的 token
        print("🔄 用一次性 code 调 /api/auth/exchange 换取 token ...")
        ex = sess.post(
            f"{SITE_ORIGIN}/api/auth/exchange",
            json={"code": success_code},
            headers={"Content-Type": "application/json", "Referer": f"{SITE_ORIGIN}/auth/success"},
            timeout=20,
        )
        if ex.status_code != 200:
            print(f"❌ exchange 失败: HTTP {ex.status_code} - {ex.text[:200]}")
            return ""

        token = ""
        for ck in sess.cookies.jar:
            if ck.name == COOKIE_NAME:
                token = ck.value
                break
        if not token:
            set_cookie = ex.headers.get("set-cookie", "")
            mm = re.search(rf"{re.escape(COOKIE_NAME)}=([^;]+)", set_cookie)
            if mm:
                token = urllib.parse.unquote(mm.group(1))

        if not token:
            print(f"❌ exchange 响应未包含 {COOKIE_NAME}（HTTP {ex.status_code}，body: {ex.text[:150]}）")
            return ""

        expiry = get_expiry_from_cookie(token)
        if expiry:
            print(f"📅 新 COOKIE 到期时间: {expiry.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"✅ HTTP 登录成功，拿到新的 {COOKIE_NAME}: {mask_secret(token)}")
        return token
    except Exception as e:
        print(f"❌ HTTP OAuth 登录异常: {e}")
        return ""

def fetch_new_cookie_with_retry(attempts: int = 3) -> str:
    """OAuth 刷新带重试（代理链路偶发 TLS 抖动，curl: (35)）"""
    for i in range(attempts):
        token = fetch_new_cookie_via_http()
        if token:
            return token
        print(f"⚠️ OAuth 登录失败({i + 1}/{attempts})，稍后重试...")
        time.sleep(3)
    return ""

# ================= 浏览器兜底（真实浏览器过盾 + Turnstile） =================
#   续期 API 加了两道验证：
#   1) Cloudflare 盾 —— seleniumbase UC 模式打开站点自动过
#   2) 业务层 captcha —— 续期请求必须带 turnstile_token（前端 getHumanToken
#      的流程：/api/auth/me 拿 sitekey -> 加载 Turnstile -> render 拿 token ->
#      POST /api/bots/{id}/renew {turnstile_token}）。这里在页面上下文重现该流程。

CF_TITLE_KEYWORDS = ("just a moment", "attention required", "请稍候")

def open_site(sb, url: str) -> bool:
    """打开页面并等待 Cloudflare 盾放行，90 秒超时返回 False"""
    sb.open(url)
    sb.wait_for_ready_state_complete()
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            title = (sb.get_title() or "").lower()
        except Exception:
            title = ""
        if title and not any(k in title for k in CF_TITLE_KEYWORDS):
            return True
        print("⏳ Cloudflare 盾挑战中，尝试自动点击...")
        try:
            sb.uc_gui_click_captcha()
        except Exception as e:
            print(f"⚠️ 盾点击失败: {e}")
        sb.sleep(3)
    return False

def inject_cookie(sb, token: str) -> bool:
    """用 WebDriver cookie API 注入 __Host- 登录 cookie。
    CI 过盾后页面可能短暂停留在挑战过渡文档，document.cookie 会抛
    Access denied；改走 WebDriver API，等 URL 回到站点域再注入，失败重试。"""
    deadline = time.time() + 60
    last_err = ""
    while time.time() < deadline:
        try:
            if sb.get_current_url().startswith(SITE_ORIGIN):
                sb.driver.add_cookie({
                    "name": COOKIE_NAME,
                    "value": token,
                    "path": "/",
                    "secure": True,
                    "sameSite": "Lax",
                })
                return True
        except Exception as e:
            last_err = f"{type(e).__name__}: {str(e)[:120]}"
        sb.sleep(3)
    print(f"❌ COOKIE 注入失败: {last_err or '60秒内 URL 未回到站点域'}")
    return False

ME_FETCH_JS = """
var callback = arguments[arguments.length - 1];
fetch('/api/auth/me', {credentials: 'include'})
  .then(function(r) { return r.text().then(function(t) {
      callback(JSON.stringify({status: r.status, body: t.slice(0, 1000)})); }); })
  .catch(function(e) { callback(JSON.stringify({status: 0, body: String(e)})); });
"""

TURNSTILE_SETUP_JS = """
var callback = arguments[arguments.length - 1];
var sitekey = %s;
(function() {
    if (window.turnstile) return Promise.resolve();
    return new Promise(function(res, rej) {
        var s = document.createElement('script');
        s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
        s.async = true; s.onload = res;
        s.onerror = function() { rej(new Error('turnstile script load failed')); };
        document.head.appendChild(s);
    });
})().then(function() {
    window.__sbToken = ''; window.__sbError = '';
    var d = document.createElement('div');
    d.style.cssText = 'position:fixed;bottom:0;right:0;width:320px;height:80px;z-index:99999;background:#000;';
    document.body.appendChild(d);
    window.turnstile.render(d, {
        sitekey: sitekey, action: 'renew',
        callback: function(t) { window.__sbToken = t; d.remove(); },
        'error-callback': function(e) { window.__sbError = String(e); d.remove(); },
        'expired-callback': function() { window.__sbError = 'expired'; d.remove(); }
    });
    callback('rendered');
}).catch(function(e) { callback('load-error: ' + e); });
"""

RENEW_POST_JS = """
var callback = arguments[arguments.length - 1];
var ttoken = %s, sid = %s;
fetch('/api/bots/' + sid + '/renew', {
    method: 'POST', credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({turnstile_token: ttoken})
}).then(function(r) {
    return r.text().then(function(t) {
        callback(JSON.stringify({status: r.status, body: t.slice(0, 300)})); });
}).catch(function(e) { callback(JSON.stringify({status: 0, body: String(e)})); });
"""

def renew_via_browser(token: str, server_list: list) -> dict:
    """浏览器内续期，返回 {server_id: (是否成功, HTTP状态码, 剩余小时数)}"""
    results = {sid: (False, None, None) for sid in server_list}

    sb_kwargs = {"uc": True, "headless": HEADLESS, "locale_code": "ja-JP"}
    if IS_PROXY:
        # Chromium 只认 socks5:// scheme（其 SOCKS5 默认由代理端解析 DNS，语义等同 socks5h）
        browser_proxy = normalize_proxy_url(PROXY_SERVER).replace("socks5h://", "socks5://")
        print(f"🔗 浏览器挂载代理: {browser_proxy}")
        sb_kwargs["proxy"] = browser_proxy

    try:
        from seleniumbase import SB
    except ImportError as e:
        print(f"❌ 未安装 seleniumbase，浏览器兜底不可用: {e}")
        return results

    try:
        with SB(**sb_kwargs) as sb:
            # 1) 打开站点过 CF 盾
            if not open_site(sb, SITE_ORIGIN):
                print("❌ 90秒内未能通过 Cloudflare 盾")
                return results

            # 2) 注入登录 cookie 后重新进入站点（全新浏览器会话无同名 HttpOnly cookie，可安全注入）
            if not inject_cookie(sb, token):
                return results
            if not open_site(sb, SITE_ORIGIN):
                print("❌ 注入 COOKIE 后再次过盾失败")
                return results

            # 3) 拿 Turnstile sitekey（/api/auth/me 顺带验证登录态）
            me = json.loads(sb.execute_async_script(ME_FETCH_JS, 20))
            if me.get("status") != 200:
                print(f"❌ /api/auth/me 失败，HTTP {me.get('status')}（登录态无效或被盾拦截）")
                return {sid: (False, me.get("status"), None) for sid in server_list}
            me_body = json.loads(me.get("body") or "{}")
            sitekey = me_body.get("turnstile_site_key") or (me_body.get("data") or {}).get("turnstile_site_key") or ""
            if not sitekey:
                print(f"❌ /api/auth/me 未返回 turnstile_site_key: {me.get('body')[:200]}")
                return results
            print(f"🔑 已获取 Turnstile sitekey: {sitekey[:12]}...")
            print("✅ 浏览器内登录态有效")

            # 4) 逐个服务器：渲染 Turnstile 拿 token -> 续期 POST
            for sid in server_list:
                print(f"🔁 浏览器续期服务器 [{sid}] ...")
                try:
                    render = sb.execute_async_script(TURNSTILE_SETUP_JS % json.dumps(sitekey), 20)
                    if render != "rendered":
                        print(f"❌ Turnstile 渲染失败: {render}")
                        continue
                    sb_token = ""
                    deadline = time.time() + 60
                    while time.time() < deadline:
                        sb_token = sb.execute_script("return window.__sbToken || ''") or ""
                        if sb_token:
                            break
                        err = sb.execute_script("return window.__sbError || ''") or ""
                        if err:
                            print(f"❌ Turnstile 错误: {err}")
                            break
                        sb.sleep(2)
                    if not sb_token:
                        print("❌ 60秒内未拿到 Turnstile token")
                        continue
                    print(f"🔐 Turnstile token: {sb_token[:16]}...")

                    raw = sb.execute_async_script(
                        RENEW_POST_JS % (json.dumps(sb_token), json.dumps(str(sid))), 30)
                    data = json.loads(raw)
                    status = data.get("status")
                    if status == 200:
                        try:
                            remaining = json.loads(data.get("body") or "{}").get("timer", {}).get("remaining_hours", "未知")
                        except json.JSONDecodeError:
                            remaining = "未知"
                        print(f"✅ 服务器 [{sid}] 续期成功，剩余 {remaining} 小时")
                        results[sid] = (True, status, remaining)
                    else:
                        body = (data.get("body") or "")[:200]
                        print(f"❌ 服务器 [{sid}] 续期失败，状态码: {status}, 响应: {body}")
                        results[sid] = (False, status, None)
                except Exception as e:
                    print(f"❌ 服务器 [{sid}] 浏览器续期异常: {type(e).__name__}: {str(e)[:150]}")
                time.sleep(2)
    except Exception as e:
        print(f"❌ 浏览器续期异常: {type(e).__name__}: {str(e)[:150]}")
    return results

# ================= 主流程 =================
def main() -> int:
    """返回退出码：0 = 全部续期成功，1 = 有失败或配置缺失（让 Actions 变红）"""
    global COOKIE

    print("#" * 25)
    print("   MWS 自动续期")
    print("#" * 25)

    server_list = [s_id.strip() for s_id in SERVER_IDS.split(",") if s_id.strip()]
    if not server_list:
        print("❌ 未配置有效的 SERVER_IDS")
        return 1

    if not COOKIE and not DISCORD_TOKEN:
        print("❌ COOKIE 和 DISCORD_TOKEN 均为空，请添加相关变量后再运行！")
        return 1

    print(f"🚀 开始续期任务，共 {len(server_list)} 个服务器: {server_list}")
    print(f"🔗 使用代理: {normalize_proxy_url(PROXY_SERVER)}" if IS_PROXY else "🍭 未使用代理，直连访问")

    # 出口IP对应时区设置给运行环境, 避免环境时区与出口IP不一致
    # (浏览器子进程启动时读 TZ 环境变量; time.tzset() 让进程内时间函数立即生效)
    ip, tz = get_egress_info(PROXY_SERVER if IS_PROXY else "")
    egress_str = f"{ip} ({tz})" if (ip and tz) else (ip or "未知")
    if tz:
        print(f"📍 出口IP: {ip}, 时区: {tz}")
        os.environ["TZ"] = tz
        time.tzset()
    else:
        print(f"📍 出口IP: {egress_str}, 时区: 未获取到(使用系统默认)")

    if COOKIE:
        expiry = get_expiry_from_cookie(COOKIE)
        if expiry:
            print(f"📅 当前 COOKIE 到期时间: {expiry.strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print("ℹ️ 未配置 COOKIE，将直接走 Discord 登录流程")

    # ---------- 第一轮：使用现有 COOKIE 调续期 API ----------
    results = {}      
    all_ok = True
    for s_id in server_list:
        ok, status_code, remaining = renew_server(s_id)
        results[s_id] = remaining if ok else None
        if not ok:
            all_ok = False
            if status_code in (401, 403):
                print(f"⚠️ [{s_id}] 认证失败（HTTP {status_code}），COOKIE 可能已失效")
        time.sleep(2)

    new_cookie = ""

    if all_ok:
        print("🏁 全部服务器续期成功，续期任务完成")
    else:
        # ---------- 第二轮：真实浏览器(UC 过 Cloudflare 盾)内续期 ----------
        # 旧 COOKIE 可能仍然有效、只是被盾拦，先不急着刷新
        print("\n🛡️ 纯 HTTP 续期未全部成功(站点已加 CF 盾)，切换真实浏览器重试...")
        token = COOKIE
        browser_results = renew_via_browser(token, server_list)
        for s_id, (ok, _, remaining) in browser_results.items():
            results[s_id] = remaining if ok else None

        # 浏览器内仍认证失败(401/403)时，走 Discord OAuth 刷新 COOKIE 再试一次
        auth_failed = any(st in (401, 403) for _, st, _ in browser_results.values())
        if auth_failed and not all(v[0] for v in browser_results.values()):
            if not DISCORD_TOKEN:
                print("❌ 浏览器内认证失败，且未配置 DISCORD_TOKEN，无法自动刷新 COOKIE")
            else:
                refreshed = fetch_new_cookie_with_retry()
                if refreshed:
                    token = refreshed
                    print("\n🔁 使用新 COOKIE 在浏览器内重新续期 ...")
                    browser_results = renew_via_browser(token, server_list)
                    for s_id, (ok, _, remaining) in browser_results.items():
                        results[s_id] = remaining if ok else None
                else:
                    print("❌ Discord OAuth 刷新 COOKIE 失败")

        if token != COOKIE:
            COOKIE = token
            new_cookie = token

        all_ok = all(v is not None for v in results.values())
        if all_ok:
            print("🏁 浏览器续期全部成功，续期任务完成")

    # ---------- 最后统一发送一次 TG 通知 ----------
    local_time = time.gmtime(time.time() + 8 * 3600)
    current_time = time.strftime("%Y-%m-%d %H:%M:%S", local_time)
    lines = ["🇯🇵 MWS 续期通知\n"]
    if all_ok:
        lines.append("✅ 全部续期成功")
    else:
        lines.append("⚠️ 部分服务器续期失败，请手动检查")
    for s_id, remaining in results.items():
        if remaining is None:
            lines.append(f"🖥 服务器: [{s_id}] 续期失败")
        else:
            lines.append(f"🖥 服务器: [{s_id}] 剩余 {remaining} H")
    lines.append(f"👤 续期账户: {EMAIL}")
    lines.append(f"🌍 出口IP: {egress_str}")
    lines.append(f"⏱️ 运行时间: {current_time}")
    send_tg_notification("\n".join(lines))

    # ---------- 续期完成后：把新 COOKIE 写回 GitHub Secret ----------
    if new_cookie:
        if GH_TOKEN:
            update_github_secret("COOKIE", new_cookie)
        else:
            print("ℹ️ 未配置 GH_TOKEN，跳过写入 COOKIE Secret")
            # print(f"📋 如需手动更新，请将 COOKIE 设置为: {new_cookie}")

    print("🏁 脚本执行完毕")
    # 退出码反映续期结果：失败时让 Actions 变红（TG 通知之外的第二道提醒）
    return 0 if all_ok else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        import traceback
        traceback.print_exc()
        send_tg_notification(
            f"🇯🇵 MWS 续期通知\n\n❌ 脚本异常退出\n👤 账户: {EMAIL}\n⚠️ {e}"
        )
        sys.exit(1)
