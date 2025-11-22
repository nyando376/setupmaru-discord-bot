from __future__ import annotations

import re
from typing import List, Tuple, Dict, Optional

from ..db import session_scope
from ..models import GuildModerationSetting, BannedWord, ModerationAction, ProfanityBypassRole

# 욕설 필터와 우회 역할 관리를 전담해 깔끔한 금칙어 서비스 흐름을 보장합니다.


def _normalize_word(w: str) -> str:
    return re.sub(r"\s+", "", w).lower()


def sanitize_content(s: str) -> str:
    return _normalize_word(re.sub(r"[^0-9a-zA-Z가-힣]", "", s))


def compile_patterns(words: List[str]) -> List[Tuple[str, re.Pattern]]:
    out: List[Tuple[str, re.Pattern]] = []
    for w in words:
        n = _normalize_word(w)
        if n:
            out.append((w, re.compile(re.escape(n))))
    return out


def gms_get(gid: int) -> Tuple[bool, ModerationAction]:
    with session_scope() as db:
        row = db.query(GuildModerationSetting).filter_by(guild_id=gid).one_or_none()
        if not row:
            row = GuildModerationSetting(guild_id=gid, enabled=True, action=int(ModerationAction.WARN))
            db.add(row)
            db.flush()
        return bool(row.enabled), ModerationAction(int(row.action))


def gms_set_enabled(gid: int, enabled: bool) -> None:
    with session_scope() as db:
        row = db.query(GuildModerationSetting).filter_by(guild_id=gid).one_or_none()
        if not row:
            db.add(GuildModerationSetting(guild_id=gid, enabled=enabled))
        else:
            row.enabled = bool(enabled)


def gms_set_action(gid: int, action: ModerationAction) -> None:
    with session_scope() as db:
        row = db.query(GuildModerationSetting).filter_by(guild_id=gid).one_or_none()
        if not row:
            db.add(GuildModerationSetting(guild_id=gid, action=int(action)))
        else:
            row.action = int(action)


def bw_exists(gid: int, word: str) -> bool:
    with session_scope() as db:
        return db.query(BannedWord.id).filter_by(guild_id=gid, word=word).first() is not None


def bw_add(gid: int, word: str, added_by: Optional[int] = None) -> int:
    with session_scope() as db:
        row = BannedWord(guild_id=gid, word=word, added_by=added_by)
        db.add(row)
        db.flush()
        return row.id


def bw_update(gid: int, old_word: str, new_word: str) -> bool:
    with session_scope() as db:
        row = db.query(BannedWord).filter_by(guild_id=gid, word=old_word).one_or_none()
        if not row:
            return False
        row.word = new_word
        return True


def bw_delete(gid: int, word: str) -> bool:
    with session_scope() as db:
        q = db.query(BannedWord).filter_by(guild_id=gid, word=word)
        if q.count() == 0:
            return False
        q.delete(synchronize_session=False)
        return True


def bw_clear(gid: int) -> int:
    """Remove every banned word registered in the guild and return the deleted count."""
    with session_scope() as db:
        q = db.query(BannedWord).filter_by(guild_id=gid)
        cnt = q.count()
        if cnt:
            q.delete(synchronize_session=False)
        return cnt


def bw_count(gid: int) -> int:
    with session_scope() as db:
        return db.query(BannedWord).filter_by(guild_id=gid).count()


def bw_list(gid: int, limit: int = 50, offset: int = 0) -> List[Dict]:
    with session_scope() as db:
        rows = (
            db.query(BannedWord)
            .filter_by(guild_id=gid)
            .order_by(BannedWord.created_at.asc(), BannedWord.id.asc())
            .limit(limit)
            .offset(offset)
            .all()
        )
        return [
            {"id": r.id, "word": r.word, "added_by": r.added_by, "created_at": r.created_at}
            for r in rows
        ]


# Profanity bypass roles
def pbr_role_add(gid: int, rid: int) -> bool:
    with session_scope() as db:
        if db.query(ProfanityBypassRole.id).filter_by(guild_id=gid, role_id=rid).first():
            return False
        db.add(ProfanityBypassRole(guild_id=gid, role_id=rid))
        return True


def pbr_role_del(gid: int, rid: int) -> bool:
    with session_scope() as db:
        q = db.query(ProfanityBypassRole).filter_by(guild_id=gid, role_id=rid)
        if q.count() == 0:
            return False
        q.delete(synchronize_session=False)
        return True


def pbr_role_ids(gid: int) -> List[int]:
    with session_scope() as db:
        return [r.role_id for r in db.query(ProfanityBypassRole).filter_by(guild_id=gid).all()]
