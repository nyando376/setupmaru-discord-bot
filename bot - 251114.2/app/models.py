from datetime import datetime, timezone
from enum import IntEnum

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    Boolean,
    BigInteger,
    UniqueConstraint,
    Index,
    Date,
)

from .db import Base, TABLE_KW

# 길드별 설정과 통계를 저장하는 ORM 모델 선언부로, 모든 서비스 로직의 데이터 구조를 정의합니다.


class WaitingList(Base):
    __tablename__ = "waiting_lists"
    __table_args__ = TABLE_KW
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, index=True, nullable=False)
    user_id = Column(BigInteger, index=True, nullable=False)
    user_name = Column(String(255))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class AutoAddChannel(Base):
    __tablename__ = "auto_add_channels"
    __table_args__ = (UniqueConstraint("guild_id", name="uq_aac_gid"), TABLE_KW)
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, unique=True, index=True, nullable=False)
    channel_id = Column(BigInteger, index=True, nullable=False)


class AutoRoleSetting(Base):
    __tablename__ = "auto_role_settings"
    __table_args__ = (UniqueConstraint("guild_id", name="uq_ar_gid"), TABLE_KW)
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, unique=True, index=True, nullable=False)
    role_id = Column(BigInteger, index=True, nullable=False)


class AutoRoleItem(Base):
    __tablename__ = "auto_role_items"
    __table_args__ = (
        UniqueConstraint("guild_id", "role_id", name="uq_ar_item"),
        Index("ix_ar_order", "guild_id", "position"),
        TABLE_KW,
    )
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, index=True, nullable=False)
    role_id = Column(BigInteger, index=True, nullable=False)
    position = Column(Integer, nullable=False, default=1)
    # conditions
    # target: 0=all, 1=bots only, 2=humans only
    target = Column(Integer, nullable=False, default=0)
    booster_only = Column(Boolean, nullable=False, default=False)
    min_account_days = Column(Integer, nullable=False, default=0)
    min_join_days = Column(Integer, nullable=False, default=0)


class ReportAdmin(Base):
    __tablename__ = "report_admins"
    __table_args__ = TABLE_KW
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, index=True, nullable=False)
    user_id = Column(BigInteger, nullable=True, index=True)
    user_name = Column(String(255), nullable=True)
    username = Column(String(255), nullable=True)
    email = Column(String(255), nullable=True, index=True)
    added_by = Column(String(255), nullable=True)


class CustomNotificationMessage(Base):
    __tablename__ = "custom_notification_messages"
    __table_args__ = (UniqueConstraint("guild_id", name="uq_cnm_gid"), TABLE_KW)
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, unique=True, index=True, nullable=False)
    message = Column(Text, nullable=False)


class Poll(Base):
    __tablename__ = "polls"
    __table_args__ = TABLE_KW
    id = Column(Integer, primary_key=True, index=True)
    poll_id = Column(String(255), unique=True, index=True, nullable=False)
    guild_id = Column(BigInteger, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    options = Column(Text, nullable=False)
    message_id = Column(BigInteger, index=True, nullable=False)
    channel_id = Column(BigInteger, index=True, nullable=False)
    creator_id = Column(BigInteger, index=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    is_active = Column(Boolean, default=True, index=True, nullable=False)


class PollVote(Base):
    __tablename__ = "poll_votes"
    __table_args__ = TABLE_KW
    id = Column(Integer, primary_key=True, index=True)
    poll_id = Column(String(255), index=True, nullable=False)
    user_id = Column(BigInteger, index=True, nullable=False)
    option_index = Column(Integer, nullable=False)
    voted_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class StreamStatus(Base):
    __tablename__ = "stream_status"
    __table_args__ = (Index("ix_stream_key", "guild_id", "key"), TABLE_KW)
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, index=True, nullable=False)
    key = Column(String(255), index=True, nullable=False)
    value = Column(Text, nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        index=True,
    )


class ModerationAction(IntEnum):
    WARN = 0
    DELETE = 1


class GuildModerationSetting(Base):
    __tablename__ = "guild_moderation_settings"
    __table_args__ = (UniqueConstraint("guild_id", name="uq_gms_guild"), TABLE_KW)
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, nullable=False, index=True)
    enabled = Column(Boolean, default=True, nullable=False)
    action = Column(Integer, default=int(ModerationAction.WARN), nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)


class BannedWord(Base):
    __tablename__ = "banned_words"
    __table_args__ = (
        UniqueConstraint("guild_id", "word", name="uq_bw_guild_word"),
        Index("ix_bw_guild_word", "guild_id", "word"),
        TABLE_KW,
    )
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, nullable=False, index=True)
    word = Column(String(255), nullable=False)  # normalized
    added_by = Column(BigInteger, nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class ProfanityBypassRole(Base):
    __tablename__ = "profanity_bypass_roles"
    __table_args__ = (UniqueConstraint("guild_id", "role_id", name="uq_pbr"), TABLE_KW)
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, index=True, nullable=False)
    role_id = Column(BigInteger, index=True, nullable=False)


class SecuritySetting(Base):
    __tablename__ = "security_settings"
    __table_args__ = (UniqueConstraint("guild_id", name="uq_sec_guild"), TABLE_KW)
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, nullable=False, index=True)
    log_channel_id = Column(BigInteger, nullable=True)
    block_invites = Column(Boolean, default=True, nullable=False)
    block_everyone = Column(Boolean, default=True, nullable=False)
    block_spam = Column(Boolean, default=True, nullable=False)
    spam_window_sec = Column(Integer, default=7, nullable=False)
    spam_threshold = Column(Integer, default=5, nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        index=True,
    )


class SecurityWhitelistUser(Base):
    __tablename__ = "security_whitelist_users"
    __table_args__ = (UniqueConstraint("guild_id", "user_id", name="uq_swu"), TABLE_KW)
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, index=True, nullable=False)
    user_id = Column(BigInteger, index=True, nullable=False)


class SecurityWhitelistRole(Base):
    __tablename__ = "security_whitelist_roles"
    __table_args__ = (UniqueConstraint("guild_id", "role_id", name="uq_swr"), TABLE_KW)
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, index=True, nullable=False)
    role_id = Column(BigInteger, index=True, nullable=False)


class SecurityWhitelistChannel(Base):
    __tablename__ = "security_whitelist_channels"
    __table_args__ = (UniqueConstraint("guild_id", "channel_id", name="uq_swc"), TABLE_KW)
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, index=True, nullable=False)
    channel_id = Column(BigInteger, index=True, nullable=False)


class SecurityTimeout(Base):
    __tablename__ = "security_timeouts"
    __table_args__ = (UniqueConstraint("guild_id", name="uq_sec_timeout_guild"), TABLE_KW)
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, nullable=False, index=True)
    everyone_min = Column(Integer, default=10, nullable=False)  # @everyone/@here
    invite_min = Column(Integer, default=30, nullable=False)  # external invite links
    spam_min = Column(Integer, default=15, nullable=False)  # spam/flood
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        index=True,
    )


class EventCountDaily(Base):
    __tablename__ = "event_count_daily"
    __table_args__ = (
        UniqueConstraint("guild_id", "key", "day", name="uq_event_daily"),
        Index("ix_event_daily", "guild_id", "key", "day"),
        TABLE_KW,
    )
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, nullable=False, index=True)
    key = Column(String(64), nullable=False, index=True)
    day = Column(Date, nullable=False, index=True)
    count = Column(Integer, default=0, nullable=False)


class EventCountTotal(Base):
    __tablename__ = "event_count_total"
    __table_args__ = (
        UniqueConstraint("guild_id", "key", name="uq_event_total"),
        Index("ix_event_total", "guild_id", "key"),
        TABLE_KW,
    )
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, nullable=False, index=True)
    key = Column(String(64), nullable=False, index=True)
    count = Column(Integer, default=0, nullable=False)


class ReactionCountDaily(Base):
    __tablename__ = "reaction_count_daily"
    __table_args__ = (
        UniqueConstraint("guild_id", "user_id", "day", name="uq_react_daily"),
        Index("ix_react_daily", "guild_id", "user_id", "day"),
        TABLE_KW,
    )
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, nullable=False, index=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    day = Column(Date, nullable=False, index=True)
    count = Column(Integer, default=0, nullable=False)


class ReactionCountTotal(Base):
    __tablename__ = "reaction_count_total"
    __table_args__ = (
        UniqueConstraint("guild_id", "user_id", name="uq_react_total"),
        Index("ix_react_total", "guild_id", "user_id"),
        TABLE_KW,
    )
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, nullable=False, index=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    count = Column(Integer, default=0, nullable=False)


class ReactionMessageUser(Base):
    __tablename__ = "reaction_message_users"
    __table_args__ = (
        UniqueConstraint("guild_id", "message_id", "user_id", name="uq_react_msg_user"),
        Index("ix_react_msg", "guild_id", "message_id"),
        TABLE_KW,
    )
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, nullable=False, index=True)
    channel_id = Column(BigInteger, nullable=False, index=True)
    message_id = Column(BigInteger, nullable=False, index=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    count = Column(Integer, default=0, nullable=False)


class ReactionMessageEmojiUser(Base):
    __tablename__ = "reaction_message_emoji_users"
    __table_args__ = (
        UniqueConstraint("guild_id", "message_id", "user_id", "emoji", name="uq_react_msg_emoji_user"),
        Index("ix_react_msg_emoji", "guild_id", "message_id", "emoji"),
        TABLE_KW,
    )
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, nullable=False, index=True)
    channel_id = Column(BigInteger, nullable=False, index=True)
    message_id = Column(BigInteger, nullable=False, index=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    emoji = Column(String(128), nullable=False, index=True)
    count = Column(Integer, default=0, nullable=False)


class XPUser(Base):
    __tablename__ = "xp_users"
    __table_args__ = (
        UniqueConstraint("guild_id", "user_id", name="uq_xp_guild_user"),
        Index("ix_xp_guild_user", "guild_id", "user_id"),
        TABLE_KW,
    )
    id = Column(Integer, primary_key=True, index=True)
    guild_id = Column(BigInteger, nullable=False, index=True)
    user_id = Column(BigInteger, nullable=False, index=True)
    xp = Column(Integer, default=0, nullable=False)
    last_message_at = Column(DateTime, nullable=True, index=True)
