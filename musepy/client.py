"""
muse.ai 注册与邀请码兑换协议客户端（纯 HTTP，无浏览器）

基于 duwqijlk/muse-protocol 实现，使用 default_headers=False 精确区分
Document 导航请求头与 CORS fetch 请求头（防止 curl_cffi 将 sec-fetch-user:?1 与
upgrade-insecure-requests:1 混入 fetch POST 触发 Meta 自动化检测）。
"""

import json
import logging
import random
import re
import time
import uuid
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from curl_cffi import requests as cr

logger = logging.getLogger("muse.client")

BASE = "https://muse.ai"

BOOTSTRAP_URL = "https://auth.meta.com/hatch/session/bootstrap/"
TRUSTED_HOSTS = frozenset({"auth.meta.com", "auth.muse.ai", "muse.ai"})
AYMH_HOSTS = frozenset({
    "muse.ai", "auth.muse.ai", "auth.meta.com",
    "www.facebook.com", "facebook.com",
    "www.instagram.com", "instagram.com",
})

TOS_VERSION = "ntm_create_account:default_v1_meta_account_v3+docs_v2"

CHROME142_UA = {
    "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
    ),
}

CHROME142_COMMON = {
    **CHROME142_UA,
    "accept-encoding": "gzip, deflate, br, zstd",
}


def fingerprint_headers(fp):
    """把 fingerprint.py 生成的一套指纹转成 UA 相关请求头。

    只含 UA / Client Hints；Accept-Language 由 MuseClient._h() 按指纹的
    lang_full 统一补。非 Chromium 家族不发 sec-ch-ua*（真实浏览器行为）。
    空值字段一律不发，避免出现 `sec-ch-ua: ""` 这种假头。
    """
    fp = fp or {}
    h = {}
    ua = (fp.get("user_agent") or "").strip()
    if ua:
        h["user-agent"] = ua
    # 头名（连字符）-> 指纹字典键（下划线）的映射
    key_map = {
        "sec-ch-ua": "sec_ch_ua",
        "sec-ch-ua-mobile": "sec_ch_ua_mobile",
        "sec-ch-ua-platform": "sec_ch_ua_platform",
        "sec-ch-ua-full-version-list": "sec_ch_ua_full_version_list",
        "sec-ch-ua-arch": "sec_ch_ua_arch",
        "sec-ch-ua-bitness": "sec_ch_ua_bitness",
        "sec-ch-ua-model": "sec_ch_ua_model",
        "sec-ch-ua-platform-version": "sec_ch_ua_platform_version",
    }
    for header, fp_key in key_map.items():
        val = (fp.get(fp_key) or "").strip()
        if val:
            h[header] = val
    return h


def _header_sets(ua_headers):
    """按 UA 头集生成 JSON / GET / HTML 三套请求头模板（与模块常量同构）。"""
    json_h = {
        **ua_headers,
        "accept": "*/*",
        "content-type": "application/json",
        "origin": BASE,
        "referer": BASE + "/",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "accept-encoding": "gzip, deflate, br, zstd",
    }
    get_h = {
        **ua_headers,
        "accept": "*/*",
        "referer": BASE + "/",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "accept-encoding": "gzip, deflate, br, zstd",
    }
    html_h = {
        "upgrade-insecure-requests": "1",
        **ua_headers,
        "accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "accept-encoding": "gzip, deflate, br, zstd",
    }
    return json_h, get_h, html_h


HEADERS_JSON = {
    **CHROME142_UA,
    "accept": "*/*",
    "content-type": "application/json",
    "origin": BASE,
    "referer": BASE + "/",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "accept-encoding": "gzip, deflate, br, zstd",
}

HEADERS_GET = {
    **CHROME142_UA,
    "accept": "*/*",
    "referer": BASE + "/",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "accept-encoding": "gzip, deflate, br, zstd",
}

HEADERS_HTML = {
    "upgrade-insecure-requests": "1",
    **CHROME142_UA,
    "accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "accept-encoding": "gzip, deflate, br, zstd",
}

DISCLOSURE_TEXT_JA = (
    "次に進むことで、Muse利用規約およびMetaのAI利用規約に同意するものとします。"
    "これには利用者の権利と責任に関する重要な情報が含まれています。"
    "プライバシーに関するMuseのアプローチについて詳しくはMuseプライバシーポリシーをご覧ください。"
)

_TLS_ERROR_MARKERS = ("curl: (35)", "tls connect error", "openssl_internal", "sslerror")


def _registrable_domain(host: str) -> str:
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "").lower()


def _compute_sec_fetch_site(prev_host: str | None, next_host: str | None) -> str:
    if not prev_host:
        return "none"
    p = prev_host.lower()
    n = (next_host or "").lower()
    if p == n:
        return "same-origin"
    if _registrable_domain(p) == _registrable_domain(n):
        return "same-site"
    return "cross-site"


def normalize_proxy(proxy: str | None) -> str | None:
    p = (proxy or "").strip()
    if not p:
        return None
    low = p.lower()
    if low.startswith("socks5://"):
        return "socks5h://" + p[len("socks5://"):]
    if "://" in p:
        return p
    if "@" in p:
        return f"http://{p}"
    parts = p.split(":")
    if len(parts) == 4:
        host, port, user, password = parts
        return f"http://{user}:{password}@{host}:{port}"
    if len(parts) == 2:
        host, port = parts
        return f"http://{host}:{port}"
    return f"http://{p}"


class _TlsRetrySession:
    """原会话重试偶发 TLS 握手瞬断（curl: (35)），保留已种下的 Cookie。"""

    def __init__(self, inner, retries: int = 2, backoff: float = 1.2):
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_retries", max(0, int(retries)))
        object.__setattr__(self, "_backoff", float(backoff))

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_inner"), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, "_inner"), name, value)

    def _call(self, method: str, *args, **kwargs):
        inner = object.__getattribute__(self, "_inner")
        retries = object.__getattribute__(self, "_retries")
        backoff = object.__getattribute__(self, "_backoff")
        fn = getattr(inner, method)
        for attempt in range(retries + 1):
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                msg = str(exc).lower()
                if not any(m in msg for m in _TLS_ERROR_MARKERS) or attempt >= retries:
                    raise
                wait = backoff * (attempt + 1)
                url = args[0] if args else kwargs.get("url", "?")
                logger.warning(
                    "TLS 握手瞬断，%.1fs 后原会话重试 (%d/%d): %s",
                    wait, attempt + 1, retries, str(url)[:80],
                )
                time.sleep(wait)

    def get(self, *args, **kwargs):
        return self._call("get", *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._call("post", *args, **kwargs)


class MuseError(RuntimeError):
    """协议流程中的可预期失败"""


class MuseClient:
    """一个账号 = 一个 Session（一个出口 IP）"""

    def __init__(self, proxy=None, impersonate="chrome142", lang="ja", timeout=60, fingerprint=None):
        # fingerprint 优先：TLS impersonate、UA、Client Hints、Accept-Language
        # 必须来自同一套指纹，否则会出现“TLS 说 Chrome/146、UA 说 142”的自相矛盾。
        self.fingerprint = dict(fingerprint) if fingerprint else None
        if self.fingerprint:
            self.fp = self.fingerprint.get("impersonate") or impersonate
            self.ua_headers = fingerprint_headers(self.fingerprint)
            self.lang = self.fingerprint.get("lang_full") or (
                "ja,en-US;q=0.9,en;q=0.8" if lang == "ja" else lang)
            self.raw_lang = self.fingerprint.get("lang") or lang
        else:
            self.fp = impersonate
            self.ua_headers = dict(CHROME142_UA)
            self.lang = "ja,en-US;q=0.9,en;q=0.8" if lang == "ja" else lang
            self.raw_lang = lang
        self.headers_json, self.headers_get, self.headers_html = _header_sets(self.ua_headers)
        self.proxy = normalize_proxy(proxy)
        self.timeout = timeout
        raw_session = cr.Session(
            impersonate=self.fp,
            default_headers=False,
            proxies={"http": self.proxy, "https": self.proxy} if self.proxy else {"http": "", "https": ""},
            timeout=timeout,
        )
        raw_session.trust_env = False
        self.s = _TlsRetrySession(raw_session)
        self.csrf = None
        self.waterfall_id = _uuid()
        self.account_id = None
        self.tos_content_version = None
        self.requires_name = True
        self.onboarding = None
        self.home_url = BASE + "/"

    # ---------- 基础设施 ----------

    def _h(self, base, extra=None, priority="u=1, i"):
        h = dict(base)
        if extra:
            h.update(extra)
        h["accept-language"] = self.lang
        if priority and "priority" not in h:
            h["priority"] = priority
        return h

    def _json(self, resp):
        try:
            return resp.json() or {}
        except Exception:
            return {}

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

    # ---------- 注册流程 ----------

    def open_home(self):
        """手动按真实 Chrome 跨站重定向规则跟随 aymh 循环，确保 facebook/meta 种下的 datr 不带异常头。"""
        url = BASE + "/"
        prev_host = None
        for _ in range(12):
            cur_host = urlsplit(url).hostname
            hdr = self._h(self.headers_html, {
                "sec-fetch-site": _compute_sec_fetch_site(prev_host, cur_host),
            }, priority="u=0, i")
            r = self.s.get(url, impersonate=self.fp, headers=hdr, allow_redirects=False)
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("location")
                if not loc:
                    break
                next_url = urljoin(url, loc)
                next_host = urlsplit(next_url).hostname
                if next_host not in AYMH_HOSTS:
                    raise MuseError(f"open-home 非预期重定向域: {next_host}")
                prev_host = cur_host
                url = next_url
                continue
            if r.status_code >= 400:
                raise MuseError(f"open-home {r.status_code}: {r.text[:120]}")
            self.home_url = url
            # 模拟真实浏览器 CookieMonster + Facebook Pixel 客户端 Cookie（wd / dpr / _fbp）
            # 有指纹时按指纹的屏幕/DPR 取值（视口高 = 屏幕高 - 80，与旧默认值 1440x900->1440x820 同口径）
            if self.fingerprint:
                try:
                    sw, sh = (self.fingerprint.get("screen") or "1920x1080").split("x")
                    wd = f"{sw}x{int(sh) - 80}"
                except Exception:
                    wd = "1920x1000"
                dpr = str(self.fingerprint.get("device_pixel_ratio") or 1.0)
            else:
                wd, dpr = "1440x820", "2"
            self.s.cookies.set("wd", wd, domain=".muse.ai", path="/")
            self.s.cookies.set("dpr", dpr, domain=".muse.ai", path="/")
            fbp = f"fb.1.{int(time.time() * 1000)}.{random.randint(10**17, 10**18 - 1)}"
            self.s.cookies.set("_fbp", fbp, domain=".muse.ai", path="/")
            try:
                self.s.get(
                    BASE + "/api/consent/status",
                    impersonate=self.fp,
                    headers=self._h(self.headers_get, {"referer": url}),
                )
            except Exception:
                pass
            return r
        raise MuseError("open-home 重定向次数过多")

    def restart(self, resume=False):
        """开启注册流程，生成全程共享的 waterfall_id 并返回 csrf_token。"""
        self.waterfall_id = _uuid()
        init_headers = self._h(self.headers_json, {
            "referer": getattr(self, "home_url", BASE + "/"),
            "X-Hatch-Waterfall-Id": self.waterfall_id,
        })
        r = self.s.post(
            BASE + "/api/auth/native/restart",
            impersonate=self.fp,
            headers=init_headers,
            data=json.dumps({"resume": bool(resume)}, separators=(",", ":")),
        )
        if r.status_code not in (200, 201):
            raise MuseError(f"restart {r.status_code}: {r.text[:120]}")
        data = self._json(r)
        self.csrf = data.get("csrf_token")
        if not self.csrf:
            raise MuseError("restart 未返回 csrf_token")
        return self.csrf

    def _auth_headers(self):
        extra = {}
        if self.csrf:
            extra["X-Hatch-CSRF-Token"] = self.csrf
            extra["X-Hatch-Waterfall-Id"] = self.waterfall_id
            extra["X-Hatch-Caa-Reg-Entry-Point"] = "login_home"
        return self._h(self.headers_json, extra)

    def send_otp(self, email, region=None):
        body = {"contact_point": email}
        if region is None and self.raw_lang.lower().startswith("ja"):
            region = "JP"
        if region:
            body["region"] = region
        r = self.s.post(
            BASE + "/api/auth/native/send-otp",
            impersonate=self.fp,
            headers=self._auth_headers(),
            data=json.dumps(body, separators=(",", ":")),
        )
        if r.status_code not in (200, 201):
            raise MuseError(f"send-otp {r.status_code}: {r.text[:120]}")
        return self._json(r)

    def confirm_otp(self, code):
        """关键：supports_muse_link_transparency 必须为 true"""
        r = self.s.post(
            BASE + "/api/auth/native/confirm-otp",
            impersonate=self.fp,
            headers=self._auth_headers(),
            data=json.dumps({
                "otp_code": code,
                "remember_device": True,
                "supports_muse_link_transparency": True,
            }, separators=(",", ":")),
        )
        if r.status_code != 200:
            raise MuseError(f"confirm-otp {r.status_code}: {r.text[:120]}")
        data = self._json(r)
        logger.info(
            "confirm-otp 返回字段: state=%s, requires_name=%s, keys=%s",
            data.get("registration_state"), data.get("requires_name"), list(data.keys()),
        )
        if "requires_name" in data:
            self.requires_name = bool(data.get("requires_name"))
        tos = data.get("tos")
        if (isinstance(tos, dict) and isinstance(tos.get("content_version"), str)
                and tos["content_version"].strip()):
            self.tos_content_version = tos["content_version"]
        return data

    def register_completion(self, date_of_birth, first_name, last_name, remember_device=True):
        body = {"date_of_birth": date_of_birth}
        if self.requires_name:
            body["first_name"] = first_name
            body["last_name"] = last_name
        body["tos_content_version"] = self.tos_content_version or TOS_VERSION
        body["remember_device"] = remember_device
        r = self.s.post(
            BASE + "/api/auth/native/register-completion",
            impersonate=self.fp,
            headers=self._auth_headers(),
            data=json.dumps(body, ensure_ascii=False, separators=(",", ":")),
        )
        if r.status_code != 200:
            raise MuseError(f"register-completion {r.status_code}: {r.text[:200]}")
        data = self._json(r)
        self.account_id = (data.get("auth_meta_session") or {}).get("frl_account_id")
        return data

    def session_cookie(self, name="hatch_sess"):
        for c in self.s.cookies.jar:
            if c.name == name:
                return c.value
        return None

    def set_session_cookie(self, value: str, name: str = "hatch_sess", domain: str = "muse.ai"):
        if value:
            self.s.cookies.set(name, value, domain=domain, path="/")

    # ---------- 激活 ----------

    def _trusted_location(self, location, base_url):
        if (not isinstance(location, str) or not location
                or "\\" in location or any(ch.isspace() for ch in location)):
            raise MuseError("activate_session 重定向 Location 非法")
        parts = urlsplit(urljoin(base_url, location))
        if (parts.scheme != "https" or parts.hostname not in TRUSTED_HOSTS
                or parts.username is not None or parts.password is not None
                or parts.port not in (None, 443)):
            raise MuseError("activate_session 重定向目标不受信任")
        return urlunsplit(("https", parts.hostname, parts.path or "/", parts.query, ""))

    def activate_session(self, frl_access_token):
        if not isinstance(frl_access_token, str) or not frl_access_token.strip():
            raise MuseError("activate_session 缺少 frl_access_token")
        url, method, hops = BOOTSTRAP_URL, "POST", 0
        prev_host = "muse.ai"
        while True:
            cur_host = urlsplit(url).hostname
            headers = self._h(self.headers_html, {
                "sec-fetch-site": _compute_sec_fetch_site(prev_host, cur_host),
            })
            if method == "POST":
                headers.update({
                    "content-type": "application/x-www-form-urlencoded",
                    "origin": BASE,
                    "referer": BASE + "/",
                    "cache-control": "max-age=0",
                })
                r = self.s.post(
                    url,
                    impersonate=self.fp,
                    headers=headers,
                    data=urlencode({"frl_access_token": frl_access_token}),
                    allow_redirects=False,
                )
            else:
                r = self.s.get(url, impersonate=self.fp, headers=headers, allow_redirects=False)
            if r.status_code in (301, 302, 303, 307, 308):
                hops += 1
                if hops > 8:
                    raise MuseError("activate_session 重定向次数过多")
                prev_host = cur_host
                next_method = method if r.status_code in (307, 308) else "GET"
                url, method = self._trusted_location(r.headers.get("location"), url), next_method
                continue
            break
        if r.status_code != 200:
            raise MuseError(f"activate_session 引导失败 {r.status_code}: {r.text[:120]}")
        final = urlsplit(url)
        if final.hostname != "muse.ai":
            raise MuseError(f"activate_session 最终落在非 muse.ai 域（{final.hostname}）")
        onboarding = parse_onboarding(r.text)
        if onboarding["state"] == "waitlist":
            raise MuseError("region_waitlist")
        if onboarding["state"] != "disclosure":
            raise MuseError(f"disclosure_context_unresolved ({onboarding.get('reason')})")
        onboarding["source_url"] = urlunsplit(("https", final.hostname, final.path or "/", "", ""))
        self.onboarding = onboarding
        return onboarding

    def accept_tos(self, onboarding=None):
        text = (onboarding or {}).get("disclosure_text")
        version = (onboarding or {}).get("disclosure_version")
        if not text or not version:
            raise MuseError("accept_tos 缺少动态披露结果，请先调用 activate_session()")
        body = {
            "saw_meta_ai_tos": False,
            "client_request_timestamp": str(int(time.time())),
            "entry_point": "web_onboarding_flow",
            "nux_type": "ROW",
            "disclosure_version": version,
            "disclosure_text": text,
        }
        headers = self._h(self.headers_json)
        referer = (onboarding or {}).get("source_url")
        if referer:
            headers["referer"] = referer
        r = self.s.post(
            BASE + "/api/hatch/accept-tos",
            impersonate=self.fp,
            headers=headers,
            data=json.dumps(body, ensure_ascii=False, separators=(",", ":")),
        )
        if r.status_code == 403:
            raise MuseError(f"accept-tos 403: {r.text[:200]}")
        if r.status_code != 200:
            raise MuseError(f"accept-tos {r.status_code}: {r.text[:200]}")
        return r

    def invite(self):
        return self.s.get(
            BASE + "/api/hatch/invite",
            impersonate=self.fp,
            headers=self._h(self.headers_get),
        )

    def is_live(self):
        try:
            return self.invite().status_code == 200
        except Exception:
            return False

    def wake_vm(self):
        r = self.s.get(
            BASE + "/?aymh_complete=1",
            impersonate=self.fp,
            headers=self._h(self.headers_html, {"sec-fetch-site": "same-origin", "referer": BASE + "/"}),
        )
        m = re.search(r'vmId[\\"]*:[\\"]*([0-9a-fA-F-]{36})', r.text)
        if not m:
            return None
        vm_id = m.group(1)
        self.s.post(
            BASE + "/api/hatch/vm/wake",
            impersonate=self.fp,
            headers=self._h(self.headers_json),
            data=json.dumps({
                "vm_id": vm_id,
                "retry_count": 0,
                "connect_attempt_id": _uuid(),
                "wake_trigger": "mount",
                "open_id": _uuid(),
                "away_ms": 0,
            }, separators=(",", ":")),
        )
        return vm_id

    def stateful_sharing(self):
        return self.s.post(
            BASE + "/api/hatch/stateful-sharing",
            impersonate=self.fp,
            headers=self._h(self.headers_json),
            data="",
        )

    # ---------- 兑换 ----------

    def redeem(self, code):
        r = self.s.post(
            BASE + "/api/hatch/invite-code/redeem",
            impersonate=self.fp,
            headers=self._h(self.headers_json),
            data=json.dumps({"code": code, "supportsRedemptionStatus": True}, separators=(",", ":")),
        )
        if r.status_code == 200 and '"success":true' in r.text:
            return True, "redeemed"
        data = self._json(r)
        return False, data.get("reason") or f"http-{r.status_code}"

    def scratch_code(self):
        r = self.s.post(
            BASE + "/api/hatch/invite",
            impersonate=self.fp,
            headers=self._h(self.headers_json),
            data="",
        )
        if r.status_code != 200:
            return None
        return self._json(r).get("code")


def _uuid():
    return str(uuid.uuid4())


def _flight_chunks(text):
    chunks = []
    if not isinstance(text, str):
        return chunks
    for script in re.findall(r"<script\b[^>]*>(.*?)</script\s*>", text, re.I | re.S):
        match = re.fullmatch(r"\s*self\.__next_f\.push\((.*)\)\s*;?\s*", script, re.S)
        if not match:
            continue
        try:
            value = json.loads(match.group(1))
        except (ValueError, TypeError):
            continue
        if (isinstance(value, list) and len(value) == 2 and value[0] == 1
                and isinstance(value[1], str)):
            chunks.append(value[1])
    return chunks


def parse_onboarding(html):
    states, disclosures = [], []
    objects = []

    def collect(value):
        if isinstance(value, dict):
            objects.append(value)
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    for row in "".join(_flight_chunks(html)).splitlines():
        row_id, separator, data = row.partition(":")
        if not separator or not re.fullmatch(r"[0-9a-f]+", row_id):
            continue
        try:
            collect(json.loads(data))
        except (ValueError, TypeError):
            continue
    for obj in objects:
        if "resolvedDestination" in obj and isinstance(obj.get("status"), dict):
            status = obj["status"]
            states.append({
                "resolved_destination": obj.get("resolvedDestination"),
                "is_geo_gated": status.get("isGeoGated"),
                "has_hatch_access": status.get("hasHatchAccess"),
                "waitlist_status": status.get("waitlistStatus"),
            })
        if "disclosureText" in obj or "disclosureVersion" in obj:
            disclosures.append((obj.get("disclosureText"), obj.get("disclosureVersion")))
    if states:
        if len({json.dumps(s, sort_keys=True) for s in states}) > 1:
            return {"state": "unresolved", "reason": "onboarding_state_conflict"}
        if (states[0]["resolved_destination"] == "waitlist"
                or states[0]["is_geo_gated"] is True):
            return {"state": "waitlist", "reason": "onboarding_waitlist", **states[0]}
    texts = list(dict.fromkeys(t for t, _ in disclosures
                               if isinstance(t, str) and t.strip()))
    versions = list(dict.fromkeys(v for _, v in disclosures
                                  if isinstance(v, str) and v.strip()))
    if len(texts) != 1 or len(versions) != 1:
        return {"state": "unresolved", "reason": "disclosure_context_unresolved"}
    if versions[0] != "HATCH_ROW_v0":
        return {
            "state": "unresolved",
            "reason": "disclosure_version_unsupported",
            "disclosure_version": versions[0],
        }
    out = {
        "state": "disclosure",
        "reason": "disclosure_context_observed",
        "disclosure_text": texts[0],
        "disclosure_version": versions[0],
    }
    if states:
        out.update(states[0])
    return out


def random_dob(min_year=1970, max_year=1999):
    return (
        f"{random.randint(min_year, max_year)}-"
        f"{random.randint(1, 12):02d}-"
        f"{random.randint(1, 28):02d}"
    )
