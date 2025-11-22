from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import discord
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError

from ..db import session_scope
from ..models import WaitingList, AutoAddChannel, AutoRoleSetting, AutoRoleItem

# 길드 관리자가 대기열, 오토채널, 오토롤을 쉽게 다루도록 DB 헬퍼를 한국어 로직으로 묶었습니다.


# Waiting list helpers
def wl_add(gid: int, uid: int, name: Optional[str]) -> bool:
    try:
        with session_scope() as db:
            if (
                db.query(WaitingList)
                .filter(WaitingList.guild_id == gid, WaitingList.user_id == uid)
                .first()
            ):
                return False
            db.add(WaitingList(guild_id=gid, user_id=uid, user_name=name))
            return True
    except SQLAlchemyError:
        return False


def wl_list(gid: int) -> List[Dict[str, Any]]:
    try:
        with session_scope() as db:
            rows = (
                db.query(WaitingList)
                .filter(WaitingList.guild_id == gid)
                .order_by(WaitingList.timestamp.asc())
                .all()
            )
            return [
                {"user_id": r.user_id, "user_name": r.user_name, "timestamp": r.timestamp}
                for r in rows
            ]
    except SQLAlchemyError:
        return []


def wl_remove(gid: int, uid: int) -> int:
    try:
        with session_scope() as db:
            q = db.query(WaitingList).filter(
                WaitingList.guild_id == gid, WaitingList.user_id == uid
            )
            cnt = q.count()
            q.delete(synchronize_session=False)
            return cnt
    except SQLAlchemyError:
        return 0


def wl_clear(gid: int) -> int:
    try:
        with session_scope() as db:
            q = db.query(WaitingList).filter(WaitingList.guild_id == gid)
            cnt = q.count()
            q.delete(synchronize_session=False)
            return cnt
    except SQLAlchemyError:
        return 0


# Auto-add voice channel
def aac_set(gid: int, ch_id: int) -> None:
    with session_scope() as db:
        row = db.query(AutoAddChannel).filter_by(guild_id=gid).one_or_none()
        if row:
            row.channel_id = ch_id
        else:
            db.add(AutoAddChannel(guild_id=gid, channel_id=ch_id))


def aac_get(gid: int) -> Optional[int]:
    with session_scope() as db:
        row = db.query(AutoAddChannel).filter_by(guild_id=gid).one_or_none()
        return row.channel_id if row else None


def aac_remove(gid: int) -> int:
    with session_scope() as db:
        q = db.query(AutoAddChannel).filter_by(guild_id=gid)
        cnt = q.count()
        q.delete(synchronize_session=False)
        return cnt


# Auto role (single)
def ar_set(gid: int, rid: int) -> None:
    with session_scope() as db:
        row = db.query(AutoRoleSetting).filter_by(guild_id=gid).one_or_none()
        if row:
            row.role_id = rid
        else:
            db.add(AutoRoleSetting(guild_id=gid, role_id=rid))


def ar_get(gid: int) -> Optional[int]:
    with session_scope() as db:
        row = db.query(AutoRoleSetting).filter_by(guild_id=gid).one_or_none()
        return int(row.role_id) if row else None


def ar_clear(gid: int) -> int:
    with session_scope() as db:
        q = db.query(AutoRoleSetting).filter_by(guild_id=gid)
        cnt = q.count()
        q.delete(synchronize_session=False)
        return cnt


# Auto role (multiple items)
def ar_items(gid: int) -> List[int]:
    with session_scope() as db:
        rows = (
            db.query(AutoRoleItem)
            .filter_by(guild_id=gid)
            .order_by(AutoRoleItem.position.asc(), AutoRoleItem.id.asc())
            .all()
        )
        return [int(r.role_id) for r in rows]


def _ar_maxpos(db, gid: int) -> int:
    try:
        row = db.query(func.max(AutoRoleItem.position)).filter_by(guild_id=gid).one()
        return int(row[0] or 0)
    except Exception:
        return 0


def ar_item_add(gid: int, rid: int) -> bool:
    with session_scope() as db:
        if db.query(AutoRoleItem.id).filter_by(guild_id=gid, role_id=rid).first():
            return False
        pos = _ar_maxpos(db, gid) + 1
        db.add(AutoRoleItem(guild_id=gid, role_id=rid, position=pos))
        return True


def ar_item_del(gid: int, rid: int) -> bool:
    with session_scope() as db:
        q = db.query(AutoRoleItem).filter_by(guild_id=gid, role_id=rid)
        if q.count() == 0:
            return False
        q.delete(synchronize_session=False)
        rows = (
            db.query(AutoRoleItem)
            .filter_by(guild_id=gid)
            .order_by(AutoRoleItem.position.asc(), AutoRoleItem.id.asc())
            .all()
        )
        for i, r in enumerate(rows, start=1):
            r.position = i
        return True


def ar_items_clear(gid: int) -> int:
    with session_scope() as db:
        q = db.query(AutoRoleItem).filter_by(guild_id=gid)
        cnt = q.count()
        q.delete(synchronize_session=False)
        return cnt


def ar_item_setpos(gid: int, rid: int, pos: int) -> bool:
    pos = max(1, int(pos))
    with session_scope() as db:
        row = db.query(AutoRoleItem).filter_by(guild_id=gid, role_id=rid).one_or_none()
        if not row:
            return False
        rows = (
            db.query(AutoRoleItem)
            .filter_by(guild_id=gid)
            .order_by(AutoRoleItem.position.asc(), AutoRoleItem.id.asc())
            .all()
        )
        seq = [r for r in rows if r.role_id != rid]
        insert_at = min(max(0, pos - 1), len(seq))
        seq[insert_at:insert_at] = [row]
        for i, r in enumerate(seq, start=1):
            r.position = i
        return True


def ar_item_update(
    gid: int,
    rid: int,
    *,
    target: Optional[int] = None,
    booster_only: Optional[bool] = None,
    min_account_days: Optional[int] = None,
    min_join_days: Optional[int] = None,
) -> bool:
    with session_scope() as db:
        row = db.query(AutoRoleItem).filter_by(guild_id=gid, role_id=rid).one_or_none()
        if not row:
            pos = _ar_maxpos(db, gid) + 1
            row = AutoRoleItem(guild_id=gid, role_id=rid, position=pos)
        if target is not None:
            row.target = int(target)
        if booster_only is not None:
            row.booster_only = bool(booster_only)
        if min_account_days is not None:
            row.min_account_days = max(0, int(min_account_days))
        if min_join_days is not None:
            row.min_join_days = max(0, int(min_join_days))
        db.add(row)
        return True


def ar_item_rows(gid: int) -> List[AutoRoleItem]:
    with session_scope() as db:
        return (
            db.query(AutoRoleItem)
            .filter_by(guild_id=gid)
            .order_by(AutoRoleItem.position.asc(), AutoRoleItem.id.asc())
            .all()
        )


def autorole_match(member: discord.Member, item: AutoRoleItem) -> bool:
    tgt = int(getattr(item, "target", 0) or 0)
    if tgt == 1 and not member.bot:
        return False
    if tgt == 2 and member.bot:
        return False
    if bool(getattr(item, "booster_only", False)):
        try:
            if not getattr(member, "premium_since", None):
                return False
        except Exception:
            return False
    mad = int(getattr(item, "min_account_days", 0) or 0)
    try:
        if mad > 0 and getattr(member, "created_at", None):
            if (datetime.now(timezone.utc) - member.created_at).days < mad:
                return False
    except Exception:
        pass
    mjd = int(getattr(item, "min_join_days", 0) or 0)
    try:
        if mjd > 0 and getattr(member, "joined_at", None):
            if (datetime.now(timezone.utc) - member.joined_at).days < mjd:
                return False
    except Exception:
        pass
    return True
