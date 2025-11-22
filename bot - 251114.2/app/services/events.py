from __future__ import annotations

from datetime import datetime, timezone, timedelta, date
from typing import Dict

from sqlalchemy import func

from ..db import session_scope
from ..models import EventCountDaily, EventCountTotal

# 이벤트 집계를 담당하는 모듈로, 한글 라벨과 함께 지표를 계산해 대시보드에 전달합니다.


EVENT_LABELS: Dict[str, str] = {
    "message_total": "메시지(유저)",
    "blocked_everyone": "@everyone/@here 차단",
    "blocked_invite": "초대링크 차단",
    "blocked_spam": "스팸 차단",
    "profanity_warn": "욕설 경고",
    "profanity_delete": "욕설 삭제",
    "member_join": "멤버 가입",
    "member_leave": "멤버 탈퇴",
    "auto_add_waitlist": "대기열 자동추가",
}


def event_inc(gid: int, key: str, n: int = 1) -> None:
    if not key:
        return
    today = datetime.now(timezone.utc).date()
    with session_scope() as db:
        d = (
            db.query(EventCountDaily)
            .filter_by(guild_id=gid, key=key, day=today)
            .one_or_none()
        )
        if not d:
            d = EventCountDaily(guild_id=gid, key=key, day=today, count=0)
        d.count = int(d.count or 0) + int(n)
        db.add(d)

        t = db.query(EventCountTotal).filter_by(guild_id=gid, key=key).one_or_none()
        if not t:
            t = EventCountTotal(guild_id=gid, key=key, count=0)
        t.count = int(t.count or 0) + int(n)
        db.add(t)


def event_sum_days(gid: int, days: int) -> Dict[str, int]:
    if days <= 0:
        return {}
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=days - 1)
    with session_scope() as db:
        rows = (
            db.query(EventCountDaily.key, EventCountDaily.count)
            .filter(
                EventCountDaily.guild_id == gid,
                EventCountDaily.day >= start,
                EventCountDaily.day <= end,
            )
            .all()
        )
    out: Dict[str, int] = {}
    for k, c in rows:
        out[k] = out.get(k, 0) + int(c or 0)
    return out


def event_sum_total(gid: int) -> Dict[str, int]:
    with session_scope() as db:
        rows = db.query(EventCountTotal.key, EventCountTotal.count).filter_by(guild_id=gid).all()
    return {k: int(c or 0) for k, c in rows}
