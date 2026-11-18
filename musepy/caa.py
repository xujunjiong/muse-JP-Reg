"""
caa-events 上报（Create Account Analytics）

前端通过 navigator.sendBeacon 逐步骤上报注册漏斗事件，同一 waterfall_id
贯穿整个流程。这些事件不参与注册判定，但构成完整的漏斗数据。
"""

import json
import time
import uuid

BASE = "https://muse.ai"
T_LOGIN = "caa_login_client_events_rl"
T_ACQ = "caa_acquisition_client_events_rl"


class Caa:
    def __init__(self, impersonate, lang, waterfall_id=None, ua_headers=None):
        self.fp = impersonate
        self.lang = lang
        self.wid = waterfall_id or str(uuid.uuid4())
        self.sent = 0
        # 与主流程同一套指纹的 UA 头；不传则沿用旧的 chrome142 默认值
        self.ua_headers = dict(ua_headers) if ua_headers else None

    def _send(self, session, events):
        if not events or session is None:
            return None
        from .client import CHROME142_UA
        h = {
            **(self.ua_headers if self.ua_headers is not None else CHROME142_UA),
            "accept": "*/*",
            "content-type": "application/json",
            "origin": BASE,
            "referer": BASE + "/",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": self.lang,
            "priority": "u=4, i",
        }
        try:
            r = session.post(
                BASE + "/api/auth/caa-events",
                impersonate=self.fp,
                headers=h,
                data=json.dumps({"events": events}, separators=(",", ":")),
            )
            self.sent += 1
            return r
        except Exception:
            return None

    # ---- 联系点页 ----

    def page_shown(self, s):
        return self._send(s, [{
            "table": T_LOGIN, "event_name": "contactpoint_page_shown",
            "event_category": "contactpoint_page_interaction", "event_flow": "login_manual",
            "event_step": "contactpoint", "extra_client_data": {"is_native": "1"},
            "waterfall_id": self.wid, "client_time_ms": _ms()}])

    def focus(self, s):
        return self._send(s, [{
            "table": T_LOGIN, "event_name": "contactpoint_focus",
            "event_category": "contactpoint_page_interaction", "event_flow": "login_manual",
            "event_step": "contactpoint", "extra_client_data": {"is_native": "1"},
            "waterfall_id": self.wid, "client_time_ms": _ms()}])

    def continue_clicked(self, s):
        return self._send(s, [{
            "table": T_LOGIN, "event_name": "contactpoint_continue_clicked",
            "event_category": "contactpoint_page_interaction", "event_flow": "login_manual",
            "event_step": "contactpoint", "contact_point_type": "EMAIL_ADDRESS",
            "extra_client_data": {"is_native": "1"},
            "waterfall_id": self.wid, "client_time_ms": _ms()}])

    # ---- 注册漏斗 ----

    def registration_start(self, s):
        return self._send(s, [
            {"table": T_LOGIN, "event_name": "password_saving_start", "event_category": "impression",
             "event_flow": "ntm", "event_step": "otp",
             "extra_client_data": {"is_native": "1", "is_checked": "1"},
             "waterfall_id": self.wid, "client_time_ms": _ms()},
            {"table": T_ACQ, "event_name": "registration_flow_state", "state": "registration_start",
             "event_category": "registration_funnel", "event_step": "contactpoint", "event_flow": "ntm",
             "entry_point": "login_home", "contact_point_type": "EMAIL_ADDRESS",
             "extra_client_data": {"is_native": "1", "flow_source": "server"},
             "waterfall_id": self.wid, "client_time_ms": _ms()},
            {"table": T_ACQ, "event_name": "confirmation_flow_state", "state": "confirmation_start",
             "event_category": "confirmation_funnel", "event_step": "confirmation",
             "contact_point_type": "EMAIL_ADDRESS",
             "extra_client_data": {"is_native": "1", "flow_source": "server"},
             "event_flow": "ntm", "entry_point": "login_home",
             "waterfall_id": self.wid, "client_time_ms": _ms()},
        ])

    def otp_typed(self, s):
        return self._send(s, [{
            "table": T_ACQ, "event_name": "confirmation_flow_state", "state": "confirmation_next",
            "event_category": "confirmation_funnel", "event_step": "confirmation",
            "contact_point_type": "EMAIL_ADDRESS",
            "extra_client_data": {"is_native": "1", "flow_source": "server"},
            "event_flow": "ntm", "entry_point": "login_home",
            "waterfall_id": self.wid, "client_time_ms": _ms()}])

    def otp_success(self, s):
        return self._send(s, [{
            "table": T_ACQ, "event_name": "confirmation_flow_state", "state": "confirmation_success",
            "event_category": "confirmation_funnel", "event_step": "confirmation",
            "contact_point_type": "EMAIL_ADDRESS",
            "extra_client_data": {"is_native": "1", "flow_source": "server"},
            "event_flow": "ntm", "entry_point": "login_home",
            "waterfall_id": self.wid, "client_time_ms": _ms()}])

    def birthday_start(self, s):
        return self._send(s, [{
            "table": T_ACQ, "event_name": "registration_flow_state", "state": "birthday_start",
            "event_category": "registration_funnel", "event_step": "birthday", "event_flow": "ntm",
            "entry_point": "login_home", "extra_client_data": {"is_native": "1"},
            "waterfall_id": self.wid, "client_time_ms": _ms()}])

    def birthday_next(self, s):
        return self._send(s, [
            {"table": T_ACQ, "event_name": "registration_flow_state", "state": "birthday_next",
             "event_category": "registration_funnel", "event_step": "birthday", "event_flow": "ntm",
             "entry_point": "login_home", "extra_client_data": {"is_native": "1"},
             "waterfall_id": self.wid, "client_time_ms": _ms()},
            {"table": T_ACQ, "event_name": "registration_flow_state", "state": "create_attempt",
             "event_category": "registration_funnel", "event_step": "account_creation", "event_flow": "ntm",
             "entry_point": "login_home", "contact_point_type": "EMAIL_ADDRESS",
             "extra_client_data": {"is_native": "1"},
             "waterfall_id": self.wid, "client_time_ms": _ms()},
        ])

    def create_success(self, s, user_id):
        return self._send(s, [{
            "table": T_ACQ, "event_name": "registration_flow_state", "state": "create_success",
            "event_category": "registration_funnel", "event_step": "account_creation", "event_flow": "ntm",
            "entry_point": "login_home", "contact_point_type": "EMAIL_ADDRESS",
            "created_user_id": str(user_id or ""), "extra_client_data": {"is_native": "1"},
            "waterfall_id": self.wid, "client_time_ms": _ms()}])

    def login_success(self, s, user_id):
        return self._send(s, [
            {"table": T_LOGIN, "event_name": "login_success", "event_category": "login_success",
             "event_flow": "ntm", "event_step": "tos",
             "extra_client_data": {"is_native": "1", "login_source": "Registration",
                                   "login_credential_type": "new_account", "is_2fa": "false"},
             "logged_in_identifier": str(user_id or ""),
             "waterfall_id": self.wid, "client_time_ms": _ms()},
            {"table": T_LOGIN, "event_name": "password_saving_opt_in", "event_category": "interaction",
             "event_flow": "ntm", "event_step": "otp",
             "extra_client_data": {"is_native": "1"},
             "waterfall_id": self.wid, "client_time_ms": _ms()},
        ])


def _ms():
    return int(time.time() * 1000)
