import asyncio
import os
from pathlib import Path
from typing import Any, Dict, Optional

from aiohttp import web

from .db import engine, resolved_url
from .services.moderation import (
    gms_get,
    gms_set_enabled,
    gms_set_action,
    bw_count,
    bw_list,
    bw_add,
    bw_delete,
)
from .services.security import (
    sec_get,
    sec_update,
    sto_get,
    sto_update,
    wl_lists,
    wl_user_add,
    wl_user_del,
    wl_role_add,
    wl_role_del,
    wl_channel_add,
    wl_channel_del,
)
from .services.guild_admin import (
    wl_list as wlist,
    wl_add as wadd,
    wl_remove as wremove,
    wl_clear as wclear,
)

# 이 모듈은 간단한 관리자용 HTTP API를 제공해 봇 상태와 보안 설정을 웹으로 제어할 수 있게 합니다.


def _json(data: Dict[str, Any]) -> web.Response:
    return web.json_response(data, headers={
        "Access-Control-Allow-Origin": os.getenv("ADMIN_CORS", "*")
    })


def _require_gid(qs: Dict[str, str]) -> int:
    gid = int(qs.get("guild_id") or 0)
    if gid <= 0:
        raise web.HTTPBadRequest(text="guild_id is required")
    return gid


async def api_guilds(request: web.Request) -> web.Response:
    bot = request.app["bot"]
    guilds = []
    for g in bot.guilds:
        icon = None
        try:
            if g.icon:
                icon = g.icon.url
        except Exception:
            icon = None
        guilds.append({"id": g.id, "name": g.name, "member_count": getattr(g, "member_count", 0), "icon": icon})
    return _json({"ok": True, "guilds": guilds})


async def api_status(request: web.Request) -> web.Response:
    bot = request.app["bot"]
    data = {
        "discord": {
            "connected": bot.is_ready(),
            "latency_ms": round(getattr(bot, "latency", 0.0) * 1000),
            "bot": getattr(bot.user, "name", None) if bot.user else None,
            "guild_count": len(getattr(bot, "guilds", [])),
            "user_count": len(getattr(bot, "users", [])),
        },
        "database": {
            "connected": engine is not None,
            "endpoint": (resolved_url.split("@")[-1].split("/")[0] if resolved_url else None),
        },
    }
    return _json({"ok": True, **data})


async def api_security_get(request: web.Request) -> web.Response:
    gid = _require_gid(request.rel_url.query)
    s = sec_get(gid)
    to = sto_get(gid)
    users, roles, channels = wl_lists(gid)
    return _json({
        "ok": True,
        "security": {
            "log_channel_id": s.log_channel_id,
            "block_invites": bool(s.block_invites),
            "block_everyone": bool(s.block_everyone),
            "block_spam": bool(s.block_spam),
            "spam_window_sec": int(s.spam_window_sec),
            "spam_threshold": int(s.spam_threshold),
        },
        "timeouts": {
            "everyone_min": int(to.everyone_min),
            "invite_min": int(to.invite_min),
            "spam_min": int(to.spam_min),
        },
        "whitelist": {"users": users, "roles": roles, "channels": channels},
    })


async def api_security_update(request: web.Request) -> web.Response:
    gid = _require_gid(request.rel_url.query)
    body = await request.json()
    sec_update(gid,
               block_invites=bool(body.get("block_invites", False)),
               block_everyone=bool(body.get("block_everyone", False)),
               block_spam=bool(body.get("block_spam", False)),
               spam_window_sec=int(body.get("spam_window_sec", 7)),
               spam_threshold=int(body.get("spam_threshold", 5)))
    if "timeouts" in body:
        t = body["timeouts"] or {}
        sto_update(gid,
                   everyone_min=int(t.get("everyone_min", 10)),
                   invite_min=int(t.get("invite_min", 30)),
                   spam_min=int(t.get("spam_min", 15)))
    return _json({"ok": True})


async def api_security_whitelist(request: web.Request) -> web.Response:
    gid = _require_gid(request.rel_url.query)
    body = await request.json()
    typ = body.get("type")  # user|role|channel
    action = body.get("action")  # add|del
    id_val = int(body.get("id"))
    ok = False
    if typ == "user":
        ok = wl_user_add(gid, id_val) if action == "add" else wl_user_del(gid, id_val)
    elif typ == "role":
        ok = wl_role_add(gid, id_val) if action == "add" else wl_role_del(gid, id_val)
    elif typ == "channel":
        ok = wl_channel_add(gid, id_val) if action == "add" else wl_channel_del(gid, id_val)
    else:
        raise web.HTTPBadRequest(text="invalid type")
    return _json({"ok": bool(ok)})


async def api_profanity_get(request: web.Request) -> web.Response:
    gid = _require_gid(request.rel_url.query)
    enabled, action = gms_get(gid)
    limit = int(request.rel_url.query.get("limit", 100))
    offset = int(request.rel_url.query.get("offset", 0))
    total = bw_count(gid)
    words = bw_list(gid, limit=limit, offset=offset)
    return _json({
        "ok": True,
        "enabled": bool(enabled),
        "action": "DELETE" if int(action) == 1 else "WARN",
        "total": total,
        "items": words,
    })


async def api_profanity_update(request: web.Request) -> web.Response:
    gid = _require_gid(request.rel_url.query)
    body = await request.json()
    if "enabled" in body:
        gms_set_enabled(gid, bool(body.get("enabled")))
    if "action" in body:
        act = str(body.get("action", "WARN")).upper()
        gms_set_action(gid, 1 if act == "DELETE" else 0)
    return _json({"ok": True})


async def api_profanity_words(request: web.Request) -> web.Response:
    gid = _require_gid(request.rel_url.query)
    body = await request.json()
    op = body.get("action")  # add|del
    if op == "add":
        word = (body.get("word") or "").strip()
        if not word:
            raise web.HTTPBadRequest(text="word required")
        wid = bw_add(gid, word)
        return _json({"ok": True, "id": wid})
    elif op == "del":
        word = (body.get("word") or "").strip()
        ok = bw_delete(gid, word)
        return _json({"ok": bool(ok)})
    else:
        raise web.HTTPBadRequest(text="invalid action")


async def _index_redirect(request: web.Request) -> web.Response:
    raise web.HTTPFound(location="/admin")


async def _admin_redirect(request: web.Request) -> web.Response:
    static_root: Optional[str] = request.app.get("static_root")
    if static_root:
        admin_path = os.path.join(static_root, "admin.html")
        if os.path.isfile(admin_path):
            return web.FileResponse(path=admin_path)
    # Fallback: show a simple message if the admin UI isn't available
    return web.Response(
        text=(
            "Admin UI is not available. Set 'ADMIN_STATIC' to a directory "
            "containing admin.html, or include the 'html' folder in your deployment."
        ),
        content_type="text/plain",
        status=503,
    )


def _find_static_root() -> Optional[str]:
    # 1) Respect explicit env var if it exists and is a directory
    env_path = os.getenv("ADMIN_STATIC")
    if env_path:
        p = Path(env_path).expanduser().resolve()
        if p.is_dir():
            return str(p)

    # 2) Try alongside source: <repo>/app/../html
    here = Path(__file__).resolve()
    candidate = (here.parent.parent / "html").resolve()
    if candidate.is_dir():
        return str(candidate)

    # 3) Try CWD/html
    cwd_candidate = (Path(os.getcwd()) / "html").resolve()
    if cwd_candidate.is_dir():
        return str(cwd_candidate)

    # Not found
    return None


async def create_app(bot) -> web.Application:
    app = web.Application()
    app["bot"] = bot
    static_root = _find_static_root()
    if static_root:
        app["static_root"] = static_root
    else:
        app["static_root"] = None

    app.add_routes([
        web.get("/", _index_redirect),
        web.get("/admin", _admin_redirect),
    
        web.get("/api/guilds", api_guilds),
        web.get("/api/status", api_status),

        web.get("/api/security", api_security_get),
        web.post("/api/security/update", api_security_update),
        web.post("/api/security/whitelist", api_security_whitelist),

        web.get("/api/profanity", api_profanity_get),
        web.post("/api/profanity/update", api_profanity_update),
        web.post("/api/profanity/words", api_profanity_words),

        # waitlist
        web.get("/api/waitlist", api_waitlist_get),
        web.post("/api/waitlist", api_waitlist_post),
    ])

    # Only expose static files if we actually found a static root
    if static_root:
        app.router.add_static("/static", static_root, show_index=True)

    async def on_prepare(request, response):
        response.headers.setdefault("Access-Control-Allow-Origin", os.getenv("ADMIN_CORS", "*"))
        response.headers.setdefault("Access-Control-Allow-Headers", "*, Content-Type")
        response.headers.setdefault("Access-Control-Allow-Methods", "GET,POST,OPTIONS")

    app.on_response_prepare.append(on_prepare)
    return app


async def start_web(bot) -> None:
    host = os.getenv("ADMIN_HOST", "0.0.0.0")
    port = int(os.getenv("ADMIN_PORT", "8080"))
    app = await create_app(bot)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host=host, port=port)
    await site.start()
    # keep reference to runner for clean shutdown if desired
    bot._admin_runner = runner  # type: ignore[attr-defined]


async def api_waitlist_get(request: web.Request) -> web.Response:
    gid = _require_gid(request.rel_url.query)
    rows = wlist(gid)
    return _json({"ok": True, "items": rows})


async def api_waitlist_post(request: web.Request) -> web.Response:
    gid = _require_gid(request.rel_url.query)
    body = await request.json()
    act = body.get("action")
    if act == "add":
        uid = int(body.get("user_id"))
        name = (body.get("user_name") or None)
        ok = wadd(gid, uid, name)
        return _json({"ok": bool(ok)})
    elif act == "remove":
        uid = int(body.get("user_id"))
        cnt = wremove(gid, uid)
        return _json({"ok": cnt > 0, "removed": cnt})
    elif act == "clear":
        cnt = wclear(gid)
        return _json({"ok": True, "cleared": cnt})
    else:
        raise web.HTTPBadRequest(text="invalid action")
