from __future__ import annotations

from typing import Optional, Dict, List

from sqlalchemy.exc import SQLAlchemyError

from ..db import session_scope
from ..models import Poll, PollVote, CustomNotificationMessage

# 투표와 공지 메시지를 DB에 기록하고 불러오는 기능을 모아 재사용성을 높였습니다.


def cnm_set(gid: int, message: str) -> None:
    with session_scope() as db:
        row = db.query(CustomNotificationMessage).filter_by(guild_id=gid).one_or_none()
        if row:
            row.message = message
        else:
            db.add(CustomNotificationMessage(guild_id=gid, message=message))


def cnm_get(gid: int) -> Optional[str]:
    with session_scope() as db:
        row = db.query(CustomNotificationMessage).filter_by(guild_id=gid).one_or_none()
        return row.message if row else None


def poll_create_db(
    poll_id: str,
    gid: int,
    title: str,
    options_json: str,
    message_id: int,
    channel_id: int,
    creator_id: int,
) -> int:
    try:
        with session_scope() as db:
            row = Poll(
                poll_id=poll_id,
                guild_id=gid,
                title=title,
                options=options_json,
                message_id=message_id,
                channel_id=channel_id,
                creator_id=creator_id,
            )
            db.add(row)
            db.flush()
            return row.id
    except SQLAlchemyError:
        return 0


def poll_close_db(poll_id: str) -> bool:
    try:
        with session_scope() as db:
            row = db.query(Poll).filter_by(poll_id=poll_id, is_active=True).one_or_none()
            if not row:
                return False
            row.is_active = False
            return True
    except SQLAlchemyError:
        return False


def poll_get_db(poll_id: str) -> Optional[Poll]:
    with session_scope() as db:
        return db.query(Poll).filter_by(poll_id=poll_id).one_or_none()


def poll_vote(poll_id: str, user_id: int, option_index: int) -> bool:
    try:
        with session_scope() as db:
            p = db.query(Poll).filter_by(poll_id=poll_id, is_active=True).one_or_none()
            if not p:
                return False
            db.query(PollVote).filter_by(poll_id=poll_id, user_id=user_id).delete(
                synchronize_session=False
            )
            db.add(PollVote(poll_id=poll_id, user_id=user_id, option_index=option_index))
            return True
    except SQLAlchemyError:
        return False


def poll_counts(poll_id: str) -> Dict[int, int]:
    with session_scope() as db:
        rows = db.query(PollVote.option_index).filter_by(poll_id=poll_id).all()
        out: Dict[int, int] = {}
        for (idx,) in rows:
            out[idx] = out.get(idx, 0) + 1
        return out


def poll_grouped(poll_id: str) -> Dict[int, List[int]]:
    with session_scope() as db:
        rows = db.query(PollVote.user_id, PollVote.option_index).filter_by(poll_id=poll_id).all()
        g: Dict[int, List[int]] = {}
        for uid, opt in rows:
            g.setdefault(int(opt), []).append(int(uid))
        return g
