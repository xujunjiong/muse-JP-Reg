"""
falco 埋点上报（可选）

站点前端会通过 POST /api/falco 批量上报行为事件。缺失这些上报不会直接
导致注册失败，但会让会话的行为特征显著区别于真实浏览器。
"""

import json
import random
import time

BASE = "https://muse.ai"


def _ms():
    return int(time.time() * 1000)


def interaction(uri, action_type, action_target, event_name, meta=None, locale="ja"):
    m = {"surface": "onboarding", "result": "success",
         "resolution_mode": "blocking", "resolved_destination": "main_app"}
    if meta:
        m.update(meta)
    payload = {
        "is_cvm": False,
        "metadata": json.dumps(m, separators=(",", ":")),
        "uri": uri,
        "action_type": action_type,
        "action_target": action_target,
        "event_name": event_name,
        "device_locale": locale or "ja",
    }
    return {"event": "hatch_web_interaction", "timeInMs": _ms(), "rate": 1,
            "payload": json.dumps(payload, separators=(",", ":"))}


def impression(uri, surface, subsurface, entry_point, extra=None, locale="ja"):
    m = {"surface": surface, "subsurface": subsurface, "entry_point": entry_point}
    if extra:
        m.update(extra)
    payload = {
        "is_cvm": False,
        "metadata": json.dumps(m, separators=(",", ":")),
        "uri": uri,
        "action_type": "one_px_impression",
        "action_target": subsurface + "_ready",
        "event_name": subsurface + "_ready_impression",
        "device_locale": locale or "ja",
    }
    return {"event": "hatch_web_impression", "timeInMs": _ms(), "rate": 1,
            "payload": json.dumps(payload, separators=(",", ":"))}


def perf(uri, nav_type="navigate", seconds=None):
    ann = {
        "tracePolicy": "hatch.chat",
        "traceType": "INITIAL_LOAD",
        "uri": uri,
        "httpProtocol": "h2",
        "navigationType": nav_type,
        "interactionClass": "responsive",
        "qpl__source": "client_js",
        "navigationTypeDetail": "normal",
        "page_load_id": "%08x-0000-4000-8000-%012x" % (
            random.getrandbits(32), random.getrandbits(48)),
    }
    payload = {
        "marker_id": random.randint(600000000, 610000000),
        "action_id": 2,
        "sample_rate": 1,
        "duration_ns": int((seconds or random.uniform(2.5, 12.0)) * 1e9),
        "annotations": ann,
    }
    return {"event": "perf", "timeInMs": _ms(),
            "payload": json.dumps(payload, separators=(",", ":"))}


def send(session, impersonate, lang, session_id, events, ua_headers=None):
    """发送一批事件；失败静默"""
    if not events or session is None:
        return None
    body = {"sessionId": session_id, "user": {"kind": "loggedOut"},
            "machineId": "not_set", "events": events}
    from .client import CHROME142_UA
    h = {
        **(ua_headers if ua_headers is not None else CHROME142_UA),
        "accept": "*/*",
        "content-type": "application/json",
        "origin": BASE,
        "referer": BASE + "/",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": lang,
        "priority": "u=1, i",
    }
    try:
        return session.post(BASE + "/api/falco", impersonate=impersonate,
                            headers=h, data=json.dumps(body, separators=(",", ":")))
    except Exception:
        return None
