from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import Tuple, List

from ..db import session_scope
from ..models import XPUser

# 활동량 기반 경험치를 계산해 한국형 레벨링 경험을 제공하는 헬퍼 모듈입니다.


def _level_require(level: int) -> int:
    # MEE6-like curve: 5*L^2 + 50*L + 100
    return 5 * level * level + 50 * level + 100


def level_from_total_xp(total: int) -> Tuple[int, int, int]:
    """Return (level, xp_in_level, next_level_need) for a total XP."""
    lvl = 0
    remain = int(total or 0)
    need = _level_require(lvl)
    while remain >= need:
        remain -= need
        lvl += 1
        need = _level_require(lvl)
    return lvl, remain, need


def xp_row(gid: int, uid: int) -> XPUser:
    with session_scope() as db:
        row = db.query(XPUser).filter_by(guild_id=gid, user_id=uid).one_or_none()
        if not row:
            row = XPUser(guild_id=gid, user_id=uid, xp=0, last_message_at=None)
        db.add(row)
        db.flush()
        return row


def xp_add_message(
    gid: int, uid: int, cooldown_sec: int = 60
) -> Tuple[int, int, bool, int, int, int]:
    """
    Add message XP and return: (gained, total, leveled, level, in_level_xp, need_next)
    """
    now = datetime.now(timezone.utc)
    gained = 0
    with session_scope() as db:
        row = db.query(XPUser).filter_by(guild_id=gid, user_id=uid).one_or_none()
        if not row:
            row = XPUser(guild_id=gid, user_id=uid, xp=0, last_message_at=None)
        can_gain = True
        if row.last_message_at is not None:
            try:
                delta = (now - row.last_message_at).total_seconds()
                can_gain = delta >= cooldown_sec
            except Exception:
                can_gain = True
        if can_gain:
            gained = random.randint(15, 25)
            row.xp = int(row.xp or 0) + gained
            row.last_message_at = now
        before_level, _, _ = level_from_total_xp(int((row.xp or 0) - gained))
        after_level, cur_in_level, need_next = level_from_total_xp(int(row.xp or 0))
        leveled = after_level > before_level
        db.add(row)
        total = int(row.xp or 0)
    return gained, total, leveled, after_level, cur_in_level, need_next


def xp_get_total(gid: int, uid: int) -> int:
    with session_scope() as db:
        row = db.query(XPUser.xp).filter_by(guild_id=gid, user_id=uid).one_or_none()
        return int(row[0]) if row and row[0] is not None else 0


def xp_rank(gid: int, uid: int) -> Tuple[int, int, int]:
    """Return (rank, total_users, user_total_xp). Rank is 1-based."""
    with session_scope() as db:
        row = db.query(XPUser).filter_by(guild_id=gid, user_id=uid).one_or_none()
        if not row:
            total_users = db.query(XPUser).filter_by(guild_id=gid).count()
            return (total_users if total_users else 0), total_users, 0
        user_xp = int(row.xp or 0)
        higher = db.query(XPUser).filter(XPUser.guild_id == gid, XPUser.xp > user_xp).count()
        total_users = db.query(XPUser).filter_by(guild_id=gid).count()
        return higher + 1, total_users, user_xp


def xp_top(gid: int, limit: int = 10) -> List[tuple[int, int]]:
    with session_scope() as db:
        rows = (
            db.query(XPUser.user_id, XPUser.xp)
            .filter_by(guild_id=gid)
            .order_by(XPUser.xp.desc(), XPUser.id.asc())
            .limit(limit)
            .all()
        )
        return [(int(uid), int(xp or 0)) for uid, xp in rows]
