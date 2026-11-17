"""阿里云自建邮箱 provider（@xujunjiong.cc catch-all）。

收件链路：
    阿里云广州机 Postfix + Dovecot，catch-all 收进总账号。
    任意 <随机前缀>@xujunjiong.cc 都能收信，无需事先建号。
    取码走自建查码页的 JSON 接口：
        GET /code/api.php?email=<email>&since=<mtime>
    后端是 /usr/local/bin/mailcode-query.py，按 X-Original-To 精确匹配
    收件人，只返回该地址的最新一封信（ok / found / code / ts / mtime）。

能力：pooled=False（地址自己造，不走号池）
      ephemeral=True（每次新地址 -> Muse 始终当新号，
                      与 cf_temp 能跑通是同一个原因）

主人需要（WebUI「邮箱配置」里填，留空就用默认值）：
    aliyun_api_url   查码接口地址，如 http://8.134.116.233:8080/code/api.php
    aliyun_domain    收件域名，如 xujunjiong.cc

注意：
  - 查码接口是公开页（知道地址就能查码），不要把随机地址发给别人。
  - 同一域名批量注册会被 Muse 按域名关联，见 README 提醒：
    混着 CF 临时邮箱 / Outlook 池轮换用，别只用这一个域名。
"""

from __future__ import annotations

import json as _json
import logging
import random
import re
import string
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from .base import ConfigField, MailProvider, register

logger = logging.getLogger(__name__)

DEFAULT_API_URL = "http://8.134.116.233:8080/code/api.php"
DEFAULT_DOMAIN = "xujunjiong.cc"

# Muse OTP 是 6 位数字。查码接口的 extract_code 会从主题里抓 4-8 位，
# 这里只认 6 位，抓到别的位数一律当成“不是本轮的码”继续等，
# 避免把别的服务的码当成 Muse 的验证码填进去。
_RE_OTP6 = re.compile(r"^(\d{6})$")

# 发码方可能比我们开始等更早发信（OpenAI 实测抢跑约 20 秒），
# 时间窗放宽 30 秒，免得把刚到的正主当成旧信丢掉。
_EARLY_SLACK = 30.0


def _gen_local_part(rng: Optional[random.Random] = None, length: int = 10) -> str:
    """生成随机邮箱前缀，与 cf_temp 同款 10 位 lowercase+digits。"""
    r = rng or random
    return "".join(r.choices(string.ascii_lowercase + string.digits, k=length))


def _normalize_api_url(raw: str) -> str:
    """接受三种写法，统一成 .../code/api.php。"""
    url = (raw or "").strip().rstrip("/")
    if not url:
        return DEFAULT_API_URL
    if url.endswith("/api.php"):
        return url
    if url.endswith("/code"):
        return url + "/api.php"
    return url + "/api.php"


@register
class AliyunMailProvider(MailProvider):
    """阿里云自建邮箱 provider。"""

    kind = "aliyun"
    display_name = "阿里云自建邮箱 (@xujunjiong.cc)"

    pooled = False         # 地址自己造，无限量，不走号池
    ephemeral = True       # 每次新地址 -> Muse 永远当新号

    line_segments = 0      # 不支持导入
    import_hint = ""
    import_placeholder = ""

    config_fields = [
        ConfigField(
            "aliyun_api_url", "查码接口地址",
            placeholder=DEFAULT_API_URL,
            help="自建邮箱查码页的 JSON 接口，默认即阿里云广州机；换 IP/域名后改这里",
        ),
        ConfigField(
            "aliyun_domain", "收件域名",
            placeholder=DEFAULT_DOMAIN,
            help="已配置 catch-all 的域名",
        ),
    ]

    def __init__(
        self,
        api_url: str = "",
        domain: str = "",
    ):
        self.api_url = _normalize_api_url(api_url or DEFAULT_API_URL)
        self.domain = (domain or DEFAULT_DOMAIN).strip().lower()
        if not re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", self.domain):
            raise ValueError(f"aliyun_domain 不合法: {self.domain}")
        self._rng = random.Random()
        self._current_email: str = ""

    # ──────────────────────── 构造入口 ────────────────────────
    @classmethod
    def from_config(cls, settings: dict, account: Optional[dict] = None):
        api_url = (settings.get("aliyun_api_url") or "").strip()
        domain = (settings.get("aliyun_domain") or "").strip()
        return cls(api_url=api_url or DEFAULT_API_URL,
                   domain=domain or DEFAULT_DOMAIN)

    # ──────────────────────── HTTP 工具 ────────────────────────
    def _query(self, email_addr: str, since: float = 0) -> dict:
        """调一次查码接口，返回解析后的 JSON dict，失败返回 {}。"""
        params = {"email": email_addr}
        if since:
            params["since"] = str(since)
        url = self.api_url + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return _json.loads(r.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            try:
                return _json.loads(e.read().decode("utf-8", errors="replace"))
            except Exception:
                logger.debug(f"[aliyun] 查码接口 HTTP {e.code}")
                return {}
        except Exception as e:
            logger.debug(f"[aliyun] 查码接口异常: {e}")
            return {}

    @staticmethod
    def _pick_code(data: dict, issued_after: Optional[float]) -> Optional[str]:
        """从一次查询结果里挑出本轮可用的 6 位码，不可用返回 None。"""
        if not data.get("ok") or not data.get("found"):
            return None
        code = str(data.get("code") or "").strip()
        if not _RE_OTP6.match(code):
            return None
        if issued_after is not None:
            ts = data.get("ts") or 0
            # ts 读不出来（0）时保守起见不认，宁可多等一轮。
            if not ts or ts < issued_after - _EARLY_SLACK:
                return None
        return code

    # ──────────────────────── 公共 API ────────────────────────
    def create_mailbox(self) -> str:
        """造一个新邮箱：随机前缀 @ 收件域名，catch-all 直接能收。"""
        local = _gen_local_part(self._rng, length=10)
        email_addr = f"{local}@{self.domain}"
        self._current_email = email_addr
        logger.info(f"[aliyun] 创建邮箱: {email_addr}")
        return email_addr

    def peek_otp(
        self,
        email_addr: str,
        issued_after: Optional[float] = None,
        wait: float = 0.0,
    ) -> Optional[str]:
        """非破坏性预读：收件箱里已经躺着本轮的码就直接返回，没有返回 None。

        只查一次（wait 恒为 0，不阻塞），不改任何内部状态，
        后面的 wait_for_otp 还能再看到这封信。
        """
        since = max(0.0, (issued_after or 0) - _EARLY_SLACK)
        return self._pick_code(self._query(email_addr, since=since),
                               issued_after)

    def wait_for_otp(
        self,
        email_addr: str,
        timeout: int = 120,
        issued_after: Optional[float] = None,
    ) -> str:
        """轮询查码接口等待 OTP（6 位数字）。

        - since 参数只让接口看 issued_after 之后到的新信，避免旧码污染；
          首次查询放宽 30 秒，覆盖发码方抢跑。
        - 拿到 found=True 但 code 不是 6 位（别的服务的信 / 暂无码），
          就把 since 推到该信的 mtime 之后，继续等下一封。
        - 网络抖动不抛异常，继续轮询直到超时。
        """
        timeout = max(int(timeout or 45), 15)
        deadline = time.time() + timeout
        since = max(0.0, (issued_after or 0) - _EARLY_SLACK)
        logger.info(f"[aliyun] 等待 OTP -> {email_addr} (timeout={timeout}s)")
        while True:
            data = self._query(email_addr, since=since)
            code = self._pick_code(data, issued_after)
            if code:
                logger.info(f"[aliyun] {email_addr} OTP={code}")
                return code
            if data.get("found"):
                # 有信但不是本轮的 6 位码：跳过它，等下一封。
                mtime = data.get("mtime") or 0
                if mtime:
                    since = max(since, float(mtime))
            if time.time() >= deadline:
                raise TimeoutError(f"aliyun OTP timeout for {email_addr}")
            time.sleep(2)

    def self_test(self) -> dict:
        """连通性自检：用一个随机地址查一次，应返回 ok=True, found=False。"""
        probe = f"probe{_gen_local_part(self._rng, length=8)}@{self.domain}"
        data = self._query(probe, since=0)
        if data.get("ok"):
            return {"ok": True,
                    "message": f"阿里云查码接口连通 ({self.api_url})，"
                               f"域名 {self.domain} 正常"}
        return {"ok": False,
                "message": f"阿里云查码接口不通: {self.api_url} "
                           f"返回 {str(data)[:200]}"}
