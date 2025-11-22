from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import List, Tuple

import discord

from ..db import session_scope
from ..models import (
    SecuritySetting,
    SecurityWhitelistUser,
    SecurityWhitelistRole,
    SecurityWhitelistChannel,
    SecurityTimeout,
)

# 공지, 화이트리스트, 스팸 제한을 한글 기준으로 다루어 서버 보안을 명확히 표현합니다.

# Public regex for invite detection
INVITE_REGEX = r"(?:https?://)?(?:discord\\.gg|discord\\.com/invite)/([A-Za-z0-9-]+)"


def sec_get(gid: int) -> SecuritySetting:
    with session_scope() as db:
        row = db.query(SecuritySetting).filter_by(guild_id=gid).one_or_none()
        if not row:
            row = SecuritySetting(guild_id=gid)
            db.add(row)
            db.flush()
        return row


def sec_update(gid: int, **kwargs) -> None:
    with session_scope() as db:
        row = db.query(SecuritySetting).filter_by(guild_id=gid).one_or_none()
        if not row:
            row = SecuritySetting(guild_id=gid)
        for k, v in kwargs.items():
            if hasattr(row, k):
                setattr(row, k, v)
        db.add(row)


def wl_user_add(gid: int, uid: int) -> bool:
    with session_scope() as db:
        if db.query(SecurityWhitelistUser).filter_by(guild_id=gid, user_id=uid).first():
            return False
        db.add(SecurityWhitelistUser(guild_id=gid, user_id=uid))
        return True


def wl_user_del(gid: int, uid: int) -> bool:
    with session_scope() as db:
        q = db.query(SecurityWhitelistUser).filter_by(guild_id=gid, user_id=uid)
        if q.count() == 0:
            return False
        q.delete(synchronize_session=False)
        return True


def wl_role_add(gid: int, rid: int) -> bool:
    with session_scope() as db:
        if db.query(SecurityWhitelistRole).filter_by(guild_id=gid, role_id=rid).first():
            return False
        db.add(SecurityWhitelistRole(guild_id=gid, role_id=rid))
        return True


def wl_role_del(gid: int, rid: int) -> bool:
    with session_scope() as db:
        q = db.query(SecurityWhitelistRole).filter_by(guild_id=gid, role_id=rid)
        if q.count() == 0:
            return False
        q.delete(synchronize_session=False)
        return True


def wl_channel_add(gid: int, cid: int) -> bool:
    with session_scope() as db:
        if db.query(SecurityWhitelistChannel).filter_by(guild_id=gid, channel_id=cid).first():
            return False
        db.add(SecurityWhitelistChannel(guild_id=gid, channel_id=cid))
        return True


def wl_channel_del(gid: int, cid: int) -> bool:
    with session_scope() as db:
        q = db.query(SecurityWhitelistChannel).filter_by(guild_id=gid, channel_id=cid)
        if q.count() == 0:
            return False
        q.delete(synchronize_session=False)
        return True


def wl_lists(gid: int) -> Tuple[List[int], List[int], List[int]]:
    with session_scope() as db:
        users = [r.user_id for r in db.query(SecurityWhitelistUser).filter_by(guild_id=gid).all()]
        roles = [r.role_id for r in db.query(SecurityWhitelistRole).filter_by(guild_id=gid).all()]
        chans = [r.channel_id for r in db.query(SecurityWhitelistChannel).filter_by(guild_id=gid).all()]
        return users, roles, chans


def is_whitelisted(gid: int, member: discord.Member, channel: discord.abc.GuildChannel) -> bool:
    with session_scope() as db:
        if db.query(SecurityWhitelistUser.id).filter_by(guild_id=gid, user_id=member.id).first():
            return True
        role_ids = [r.id for r in getattr(member, "roles", [])]
        if role_ids and db.query(SecurityWhitelistRole.id).filter(
            SecurityWhitelistRole.guild_id == gid, SecurityWhitelistRole.role_id.in_(role_ids)
        ).first():
            return True
        if db.query(SecurityWhitelistChannel.id).filter_by(guild_id=gid, channel_id=channel.id).first():
            return True
    return False


async def security_log(guild: discord.Guild, text: str, color: int = 0xFF1744):
    s = sec_get(guild.id)
    if not s.log_channel_id:
        return
    ch = guild.get_channel(int(s.log_channel_id))
    if not ch:
        return
    try:
        embed = discord.Embed(
            title="🛡️ 보안 로그",
            description=text,
            color=color,
            timestamp=datetime.now(),
        )
        await ch.send(embed=embed)
    except Exception:
        # Avoid raising in bot event loop
        pass


_spam_ts = defaultdict(lambda: deque(maxlen=50))  # (guild,user) -> deque[timestamps]


def spam_hit(gid: int, uid: int, window_sec: int, threshold: int) -> bool:
    now = datetime.now().timestamp()
    dq = _spam_ts[(gid, uid)]
    dq.append(now)
    while dq and (now - dq[0]) > window_sec:
        dq.popleft()
    return len(dq) >= threshold


def sto_get(gid: int) -> SecurityTimeout:
    with session_scope() as db:
        row = db.query(SecurityTimeout).filter_by(guild_id=gid).one_or_none()
        if not row:
            row = SecurityTimeout(guild_id=gid)
            db.add(row)
            db.flush()
        return row


def sto_update(gid: int, **kwargs) -> None:
    with session_scope() as db:
        row = db.query(SecurityTimeout).filter_by(guild_id=gid).one_or_none()
        if not row:
            row = SecurityTimeout(guild_id=gid)
        for k, v in kwargs.items():
            if hasattr(row, k) and isinstance(v, int):
                setattr(row, k, int(v))
        db.add(row)
