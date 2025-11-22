from __future__ import annotations

from typing import Optional

from ..db import session_scope
from ..models import StreamStatus
from datetime import datetime, timezone

# 실시간 방송 상태를 기록/조회해 알림 기능이 최신 정보를 전달하도록 돕는 모듈입니다.


def ss_set(gid: int, key: str, value: str) -> None:
    with session_scope() as db:
        row = db.query(StreamStatus).filter_by(guild_id=gid, key=key).one_or_none()
        if row:
            row.value = value
            row.updated_at = datetime.now(timezone.utc)
        else:
            db.add(StreamStatus(guild_id=gid, key=key, value=value))


def ss_get(gid: int, key: str) -> Optional[str]:
    with session_scope() as db:
        row = db.query(StreamStatus).filter_by(guild_id=gid, key=key).one_or_none()
        return row.value if row else None


def ss_remove(gid: int, key: str) -> int:
    with session_scope() as db:
        q = db.query(StreamStatus).filter_by(guild_id=gid, key=key)
        cnt = q.count()
        q.delete(synchronize_session=False)
        return cnt
