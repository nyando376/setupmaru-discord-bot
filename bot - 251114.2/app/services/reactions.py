from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from typing import List, Tuple

import discord
from sqlalchemy import func

from ..db import session_scope
from ..models import (
    ReactionCountDaily,
    ReactionCountTotal,
    ReactionMessageUser,
    ReactionMessageEmojiUser,
)

# 반응 횟수를 기간별로 집계해 리더보드나 통계 명령에서 즉시 활용하도록 구성했습니다.


def reaction_inc(gid: int, uid: int, n: int = 1) -> None:
    today = datetime.now(timezone.utc).date()
    with session_scope() as db:
        d = (
            db.query(ReactionCountDaily)
            .filter_by(guild_id=gid, user_id=uid, day=today)
            .one_or_none()
        )
        if not d:
            d = ReactionCountDaily(guild_id=gid, user_id=uid, day=today, count=0)
        d.count = int(d.count or 0) + int(n)
        db.add(d)

        t = db.query(ReactionCountTotal).filter_by(guild_id=gid, user_id=uid).one_or_none()
        if not t:
            t = ReactionCountTotal(guild_id=gid, user_id=uid, count=0)
        t.count = int(t.count or 0) + int(n)
        db.add(t)


def reaction_sum_days(gid: int, uid: int, days: int) -> int:
    if days <= 0:
        return 0
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=days - 1)
    with session_scope() as db:
        rows = (
            db.query(ReactionCountDaily.count)
            .filter(
                ReactionCountDaily.guild_id == gid,
                ReactionCountDaily.user_id == uid,
                ReactionCountDaily.day >= start,
                ReactionCountDaily.day <= end,
            )
            .all()
        )
    return sum(int(c or 0) for (c,) in rows)


def reaction_sum_total(gid: int, uid: int) -> int:
    with session_scope() as db:
        row = db.query(ReactionCountTotal.count).filter_by(guild_id=gid, user_id=uid).one_or_none()
    return int(row[0]) if row and row[0] is not None else 0


def reaction_rank_days(gid: int, days: int) -> List[Tuple[int, int]]:
    if days <= 0:
        return []
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=days - 1)
    with session_scope() as db:
        rows = (
            db.query(ReactionCountDaily.user_id, func.sum(ReactionCountDaily.count))
            .filter(
                ReactionCountDaily.guild_id == gid,
                ReactionCountDaily.day >= start,
                ReactionCountDaily.day <= end,
            )
            .group_by(ReactionCountDaily.user_id)
            .all()
        )
    return sorted(
        [(int(uid), int(c or 0)) for uid, c in rows if int(c or 0) > 0],
        key=lambda x: x[1],
        reverse=True,
    )


def reaction_rank_total(gid: int) -> List[Tuple[int, int]]:
    with session_scope() as db:
        rows = db.query(ReactionCountTotal.user_id, ReactionCountTotal.count).filter_by(guild_id=gid).all()
    return sorted(
        [(int(uid), int(c or 0)) for uid, c in rows if int(c or 0) > 0],
        key=lambda x: x[1],
        reverse=True,
    )


def react_msg_inc(gid: int, cid: int, mid: int, uid: int, delta: int = 1) -> None:
    if not delta:
        return
    with session_scope() as db:
        row = (
            db.query(ReactionMessageUser)
            .filter_by(guild_id=gid, message_id=mid, user_id=uid)
            .one_or_none()
        )
        if not row:
            row = ReactionMessageUser(
                guild_id=gid, channel_id=cid, message_id=mid, user_id=uid, count=0
            )
        row.channel_id = cid
        row.count = max(0, int(row.count or 0) + int(delta))
        db.add(row)


def react_msg_rank(gid: int, mid: int) -> List[Tuple[int, int]]:
    with session_scope() as db:
        rows = db.query(ReactionMessageUser.user_id, ReactionMessageUser.count).filter_by(
            guild_id=gid, message_id=mid
        ).all()
    return sorted(
        [(int(uid), int(c or 0)) for uid, c in rows if int(c or 0) > 0],
        key=lambda x: x[1],
        reverse=True,
    )


_EMOJI_ID_RE = re.compile(r"^<?a?:\w+:(\d+)>?$")


def emoji_to_key(emoji: discord.PartialEmoji) -> str:
    return str(emoji.id) if emoji.id else (emoji.name or "")


def parse_emoji_key(s: str) -> str:
    if not s:
        return ""
    m = _EMOJI_ID_RE.match(s.strip())
    if m:
        return m.group(1)
    if s.isdigit():
        return s
    return s


def react_msg_emoji_inc(
    gid: int, cid: int, mid: int, uid: int, emoji_key: str, delta: int = 1
) -> None:
    if not emoji_key or not delta:
        return
    with session_scope() as db:
        row = (
            db.query(ReactionMessageEmojiUser)
            .filter_by(guild_id=gid, message_id=mid, user_id=uid, emoji=emoji_key)
            .one_or_none()
        )
        if not row:
            row = ReactionMessageEmojiUser(
                guild_id=gid,
                channel_id=cid,
                message_id=mid,
                user_id=uid,
                emoji=emoji_key,
                count=0,
            )
        row.channel_id = cid
        row.count = max(0, int(row.count or 0) + int(delta))
        db.add(row)


def react_msg_emoji_rank(gid: int, mid: int, emoji_key: str) -> List[Tuple[int, int]]:
    with session_scope() as db:
        rows = (
            db.query(ReactionMessageEmojiUser.user_id, ReactionMessageEmojiUser.count)
            .filter_by(guild_id=gid, message_id=mid, emoji=emoji_key)
            .all()
        )
    return sorted(
        [(int(uid), int(c or 0)) for uid, c in rows if int(c or 0) > 0],
        key=lambda x: x[1],
        reverse=True,
    )
