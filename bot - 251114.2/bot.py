# bot.py (enhanced with security features: invite/mention/spam filter, whitelist, security logs)
# NOTE: This file merges your original functionality with Soli-like security moderation.
# - New DB models: SecuritySetting, SecurityWhitelistUser/Role/Channel
# - New slash commands group: /보안 ...
# - New checks in on_message: invite links, @everyone/@here, spam limiter
# - Security log channel and whitelist support
# 이 모듈은 디스코드 봇의 주요 기능과 보안 흐름을 한곳에서 제어하는 중심 진입점입니다.

import os
import asyncio
import logging
from datetime import datetime, timezone, timedelta
import json
import uuid
from typing import Optional, List, Dict, Any, Tuple
import re
import io
from zipfile import ZipFile
import xml.etree.ElementTree as ET

import discord
from discord.ext import commands
from discord import app_commands

 
# Modularized components
from app.models import (
    Poll,
    ModerationAction,
)
from app.services.moderation import (
    sanitize_content as _sanitize_content,
    compile_patterns as _compile_patterns,
    _normalize_word,
    gms_get,
    gms_set_enabled,
    gms_set_action,
    bw_exists,
    bw_add,
    bw_update,
    bw_delete,
    bw_clear,
    bw_count,
    bw_list,
    pbr_role_add,
    pbr_role_del,
    pbr_role_ids,
)
from app.services.security import (
    INVITE_REGEX,
    sec_get,
    sec_update,
    wl_user_add,
    wl_user_del,
    wl_role_add,
    wl_role_del,
    wl_channel_add,
    wl_channel_del,
    wl_lists,
    is_whitelisted as _is_whitelisted,
    security_log,
    sto_get,
    sto_update,
    spam_hit as _spam_hit,
)
from app.services.events import (
    event_inc,
    event_sum_days,
    event_sum_total,
    EVENT_LABELS,
)
from app.services.reactions import (
    reaction_inc,
    reaction_sum_days,
    reaction_sum_total,
    reaction_rank_days,
    reaction_rank_total,
    react_msg_inc,
    react_msg_rank,
    emoji_to_key,
    react_msg_emoji_inc,
    react_msg_emoji_rank,
)
from app.services.xp import (
    level_from_total_xp,
    xp_row,
    xp_add_message,
    xp_get_total,
    xp_rank,
    xp_top,
)
from app.services.guild_admin import (
    wl_add,
    wl_list,
    wl_remove,
    wl_clear,
    aac_set,
    aac_get,
    aac_remove,
    ar_set,
    ar_get,
    ar_clear,
    ar_items,
    ar_item_add,
    ar_item_del,
    ar_items_clear,
    ar_item_setpos,
    ar_item_update,
    ar_item_rows,
    autorole_match as _autorole_match,
)
from app.services.polls import (
    cnm_set,
    cnm_get,
    poll_create_db,
    poll_close_db,
    poll_get_db,
    poll_vote,
    poll_counts,
    poll_grouped,
)
from app.services.stream import (
    ss_set,
    ss_get,
    ss_remove,
)

# ============================ 로깅 ============================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("bot.log", encoding="utf-8")]
)
log = logging.getLogger("bot")

from app.db import init_database, session_scope

# (moved) reactions/xp/waiting/autorole helpers are in app.services.*

# moved: cnm/poll/stream/moderation helpers are imported from app.services.*

# ============================ 캐시(욕설) ============================
_guild_cache: Dict[int, Dict] = {}
_cache_lock = asyncio.Lock()

# 대기자 자동 채널 이동 시 기본 목적지 ID와 키
AUTO_MOVE_TARGET_KEY = "auto_move_target_channel"
DEFAULT_AUTO_MOVE_TARGET_CHANNEL_ID = 1275167339666608212


def _get_auto_move_target_channel_id(gid: int) -> Optional[int]:
    raw = ss_get(gid, AUTO_MOVE_TARGET_KEY)
    if raw:
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None
    return DEFAULT_AUTO_MOVE_TARGET_CHANNEL_ID


def _set_auto_move_target_channel_id(gid: int, channel_id: int) -> None:
    ss_set(gid, AUTO_MOVE_TARGET_KEY, str(int(channel_id)))


def _clear_auto_move_target_channel_id(gid: int) -> bool:
    return bool(ss_remove(gid, AUTO_MOVE_TARGET_KEY))

async def _load_guild_cache(gid: int) -> None:
    async with _cache_lock:
        enabled, action = gms_get(gid)
        words = [r["word"] for r in bw_list(gid, limit=10_000, offset=0)]
        bypass_roles = set(pbr_role_ids(gid))
        _guild_cache[gid] = {
            "enabled": enabled,
            "action": action,
            "words": set(words),
            "compiled": _compile_patterns(words),
            "pbr_roles": bypass_roles,
        }
        log.info(f"[CACHE] guild={gid} enabled={enabled} action={action} words={len(words)}")

async def _ensure_cache(gid: int) -> Dict:
    if gid not in _guild_cache:
        await _load_guild_cache(gid)
    return _guild_cache[gid]

def _find_profanities(content_norm: str, compiled: List[Tuple[str, re.Pattern]]) -> List[str]:
    hits = []
    for original, pat in compiled:
        if pat.search(content_norm):
            hits.append(original)
            if len(hits) >= 10: break
    return hits

# moved: security helpers are in app.services.security

# ============================ Discord ============================
# Using modular services and models imported above
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
try:
    intents.reactions = True
except Exception:
    pass

PREFIX = os.getenv("COMMAND_PREFIX", "!")
bot = commands.Bot(command_prefix=PREFIX, intents=intents)

async def sync_slash_commands(guild: Optional[discord.Object] = None):
    synced = await bot.tree.sync(guild=guild)
    log.info(f"Slash synced ({'guild' if guild else 'global'}): {len(synced)}")
    return True

from app.ui.polls import PollView, format_poll_embed as _format_poll_embed
from app.web import start_web

# ---------------------- 이벤트 ----------------------
@bot.event
async def on_ready():
    log.info(f"Bot logged in as {bot.user} ({bot.user.id})")
    try:
        await init_database()
    except Exception as e:
        log.error(f"DB init failed: {e}")
        return

    # 활성 투표 뷰 복구
    try:
        with session_scope() as db:
            active = db.query(Poll).filter_by(is_active=True).all()
            cnt = 0
            for p in active:
                try:
                    options = json.loads(p.options) if isinstance(p.options, str) else (p.options or [])
                    if isinstance(options, dict):
                        options = options.get("options", [])
                    bot.add_view(PollView(p.poll_id, list(options)))
                    cnt += 1
                except Exception as ex:
                    log.warning(f"restore view fail {getattr(p,'poll_id','?')}: {ex}")
            log.info(f"Registered {cnt} persistent poll views")
    except Exception as e:
        log.warning(f"restore views error: {e}")

    # 욕설 캐시 예열
    for g in bot.guilds:
        try: await _load_guild_cache(g.id)
        except Exception as e: log.warning(f"cache warmup fail {g.id}: {e}")

    try:
        gid = os.getenv("GUILD_ID")
        if gid: await sync_slash_commands(discord.Object(id=int(gid)))
        else:   await sync_slash_commands()
    except Exception as e:
        log.error(f"Slash sync error: {e}")

    # 웹 서버 시작 (한 번만)
    if not getattr(bot, "_web_started", False):
        try:
            bot.loop.create_task(start_web(bot))
            setattr(bot, "_web_started", True)
            log.info("Admin web server started")
        except Exception as e:
            log.warning(f"Admin web start failed: {e}")

    await bot.change_presence(activity=discord.Game(name=f"{PREFIX}help"))
    log.info("✅ Ready")

@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    # 이벤트 집계: 유저 메시지 수
    try:
        event_inc(message.guild.id, "message_total")
    except Exception as _:
        pass

    # 1) (NEW) 보안/자동검열: 화이트리스트, 전체멘션, 초대링크, 스팸
    try:
        # 기초 설정/화이트리스트
        sec = sec_get(message.guild.id)
        _wl = _is_whitelisted(message.guild.id, message.author, message.channel)
        _moderation_hit = False

        # 전체멘션 차단
        if not _wl and sec.block_everyone and ("@everyone" in message.content or "@here" in message.content):
            try:
                await message.delete()
            except discord.Forbidden:
                pass
            await security_log(message.guild, f"전체멘션 차단: {message.author.mention} • {message.channel.mention}")
            try:
                event_inc(message.guild.id, "blocked_everyone")
            except Exception:
                pass
            try:
                from_time = sto_get(message.guild.id)
                await message.author.timeout(timedelta(minutes=from_time.everyone_min), reason="전체멘션 차단")
            except Exception:
                pass
            return  # 차단 후 종료

        # 초대링크 차단
        if not _wl and sec.block_invites:
            m = re.search(INVITE_REGEX, message.content, re.I)
            if m:
                code = m.group(1)
                allow = False
                try:
                    invite = await bot.fetch_invite(code)
                    if invite and invite.guild and invite.guild.id == message.guild.id:
                        allow = True  # 같은 서버 초대는 허용
                except Exception:
                    allow = False  # 해석 실패는 차단
                if not allow:
                    try:
                        await message.delete()
                    except discord.Forbidden:
                        pass
                    await security_log(message.guild, f"초대링크 삭제: {message.author.mention} • `{code}` • {message.channel.mention}")
                    try:
                        event_inc(message.guild.id, "blocked_invite")
                    except Exception:
                        pass
                    try:
                        from_time = sto_get(message.guild.id)
                        await message.author.timeout(timedelta(minutes=from_time.invite_min), reason="외부 초대링크 게시")
                    except Exception:
                        pass
                    return

        # 스팸 차단(단타/도배)
        if not _wl and sec.block_spam and _spam_hit(message.guild.id, message.author.id, sec.spam_window_sec, sec.spam_threshold):
            try:
                await message.delete()
            except discord.Forbidden:
                pass
            await security_log(message.guild, f"스팸 감지: {message.author.mention} • {message.channel.mention}")
            try:
                event_inc(message.guild.id, "blocked_spam")
            except Exception:
                pass
            try:
                from_time = sto_get(message.guild.id)
                await message.author.timeout(timedelta(minutes=from_time.spam_min), reason="스팸/도배")
            except Exception:
                pass
            return

        # 2) 기존 욕설 필터
        guild = await _ensure_cache(message.guild.id)
        # profanity-bypass: if user has any bypass role, skip profanity filter
        member_role_ids = {r.id for r in getattr(message.author, 'roles', [])}
        has_pbr = bool(member_role_ids & guild.get("pbr_roles", set()))
        if not _wl and not has_pbr and guild["enabled"]:
            norm = _sanitize_content(message.content)
            if norm:
                hits = _find_profanities(norm, guild["compiled"])
                if hits:    
                    # DM notify owner/admin about profanity usage
                    try:
                        owner_id = int(os.getenv("OWNER_NOTIFY_ID", "448318724861067287"))
                        admin_user = bot.get_user(owner_id)
                        if admin_user is None:
                            try:
                                admin_user = await bot.fetch_user(owner_id)
                            except Exception:
                                admin_user = None
                        if admin_user is not None:
                            hit_preview = ", ".join(hits[:5]) + (" ..." if len(hits) > 5 else "")
                            link = getattr(message, "jump_url", "")
                            guild_name = getattr(message.guild, "name", str(message.guild.id))
                            channel_mention = getattr(message.channel, "mention", str(message.channel.id))
                            await admin_user.send(
                                "🚫 금지 표현 감지 알림\n"
                                f"- 서버: {guild_name} ({message.guild.id})\n"
                                f"- 채널: {channel_mention}\n"
                                f"- 사용자: {message.author.mention} ({message.author.id})\n"
                                f"- 표현: {hit_preview}"
                                + (f"\n- 메시지: {link}" if link else "")
                            )
                    except Exception:
                        pass
                    _moderation_hit = True
                    action = guild["action"]
                    if action == ModerationAction.DELETE:
                        try: await message.delete()
                        except discord.Forbidden: pass
                        try:
                            warn = await message.channel.send(f"⚠️ {message.author.mention} 금지된 표현이 감지되어 메시지가 삭제되었습니다.")
                            await asyncio.sleep(5); await warn.delete()
                        except Exception: pass
                        try:
                            event_inc(message.guild.id, "profanity_delete")
                        except Exception:
                            pass
                    else:
                        try:
                            await message.reply(f"⚠️ 금지된 표현이 감지되었습니다. 수정해 주세요.\\n감지: {', '.join(hits[:5])}" + (" ..." if len(hits)>5 else ""))
                        except Exception: pass
                        try:
                            event_inc(message.guild.id, "profanity_warn")
                        except Exception:
                            pass

    except Exception:
        pass

@bot.event
async def on_member_join(member: discord.Member):
    if member.guild.system_channel:
        try:
            event_inc(member.guild.id, "member_join")
        except Exception:
            pass
        embed = discord.Embed(title="🎉 새로운 멤버!", description=f"{member.mention}님 환영합니다!", color=0x00ff00)
        await member.guild.system_channel.send(embed=embed)
    # 자동 역할 부여 시도 (다중 지원)
    try:
        items = ar_item_rows(member.guild.id)
        me = getattr(member.guild, 'me', None)
        role_objs: List[discord.Role] = []
        for it in items:
            r = member.guild.get_role(int(it.role_id)) if it and getattr(it, 'role_id', None) else None
            if not r:
                continue
            # 조건 평가
            if not _autorole_match(member, it):
                continue
            # 권한/관리형/위계 검사
            try:
                if me and not (r < me.top_role):
                    continue
            except Exception:
                pass
            if getattr(r, 'managed', False):
                continue
            if any(rr.id == r.id for rr in getattr(member, 'roles', [])):
                continue
            role_objs.append(r)
        # 레거시 단일 설정(목록 비어 있을 때만) 호환
        if not role_objs:
            rid = ar_get(member.guild.id)
            if rid:
                r = member.guild.get_role(int(rid))
                if r and not getattr(r, 'managed', False):
                    try:
                        if not me or (r < me.top_role):
                            role_objs.append(r)
                    except Exception:
                        role_objs.append(r)
        if role_objs:
            await member.add_roles(*role_objs, reason="자동 역할(조건)")
            try:
                desc = ", ".join(x.mention for x in role_objs)
                await security_log(member.guild, f"자동 역할 부여: {member.mention} → {desc}", color=0x2e7d32)
            except Exception:
                pass
    except discord.Forbidden:
        try:
            await security_log(member.guild, f"자동 역할 실패(권한 부족): {member.mention}", color=0xff6d00)
        except Exception:
            pass
    except Exception:
        # 조용히 무시 (역할 미설정 등)
        pass

@bot.event
async def on_member_remove(member: discord.Member):
    if member.guild.system_channel:
        try:
            event_inc(member.guild.id, "member_leave")
        except Exception:
            pass
        await member.guild.system_channel.send(f"👋 {member.display_name}님이 서버를 떠났습니다.")

@bot.event
async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
    if member.bot:
        return
    guild = member.guild
    if not guild:
        return

    auto_add_channel_id = aac_get(guild.id)
    if not auto_add_channel_id:
        return

    joined_auto_channel = (
        after.channel
        and after.channel.id == auto_add_channel_id
        and (before.channel is None or before.channel.id != auto_add_channel_id)
    )
    left_auto_channel = (
        before.channel
        and before.channel.id == auto_add_channel_id
        and (after.channel is None or after.channel.id != auto_add_channel_id)
    )

    if joined_auto_channel:
        success = wl_add(guild.id, member.id, member.display_name)
        if success:
            log.info(f"Auto-added {member.display_name} to waiting list in {guild.name}")
            try:
                event_inc(guild.id, "auto_add_waitlist")
            except Exception:
                pass
        return

    if left_auto_channel:
        removed = wl_remove(guild.id, member.id)
        if removed:
            log.info(f"Auto-removed {member.display_name} from waiting list in {guild.name}")

@bot.event
async def on_raw_reaction_add(payload: discord.RawReactionActionEvent):
    # 길드가 아닌 DM은 무시
    if not getattr(payload, "guild_id", None):
        return
    # 봇은 집계 제외
    u = bot.get_user(payload.user_id)
    if u and getattr(u, "bot", False):
        return
    try:
        reaction_inc(int(payload.guild_id), int(payload.user_id), 1)
    except Exception as _:
        pass
    try:
        react_msg_inc(int(payload.guild_id), int(payload.channel_id), int(payload.message_id), int(payload.user_id), +1)
    except Exception:
        pass
    try:
        ek = emoji_to_key(payload.emoji)
        react_msg_emoji_inc(int(payload.guild_id), int(payload.channel_id), int(payload.message_id), int(payload.user_id), ek, +1)
    except Exception:
        pass

@bot.event
async def on_raw_reaction_remove(payload: discord.RawReactionActionEvent):
    if not getattr(payload, "guild_id", None):
        return
    u = bot.get_user(payload.user_id)
    if u and getattr(u, "bot", False):
        return
    try:
        react_msg_inc(int(payload.guild_id), int(payload.channel_id), int(payload.message_id), int(payload.user_id), -1)
    except Exception:
        pass
    try:
        ek = emoji_to_key(payload.emoji)
        react_msg_emoji_inc(int(payload.guild_id), int(payload.channel_id), int(payload.message_id), int(payload.user_id), ek, -1)
    except Exception:
        pass

# ---------------------- 프리픽스 명령 ----------------------
@bot.command(name="핑", aliases=["ping"])
async def ping_cmd(ctx: commands.Context):
    await ctx.reply(f"🏓 {round(bot.latency*1000)}ms")

@bot.command(name="정보")
async def info_cmd(ctx: commands.Context):
    embed = discord.Embed(title="🤖 봇 정보", color=0x0099ff)
    embed.add_field(name="봇 이름", value=bot.user.name, inline=True)
    embed.add_field(name="서버 수", value=len(bot.guilds), inline=True)
    embed.add_field(name="사용자 수", value=len(bot.users), inline=True)
    await ctx.send(embed=embed)

@bot.command(name="sync")
@commands.has_permissions(administrator=True)
async def sync_cmd(ctx: commands.Context):
    try:
        gid = os.getenv("GUILD_ID")
        if gid: await sync_slash_commands(discord.Object(id=int(gid)))
        else:   await sync_slash_commands()
        await ctx.reply("✅ Slash commands synced")
    except Exception as e:
        await ctx.reply(f"❌ {e}")

# ---------------------- 기본/정보 슬래시 ----------------------
@bot.tree.command(name="안녕", description="인사합니다")
async def hello_command(inter: discord.Interaction):
    await inter.response.send_message(f"안녕하세요, {inter.user.mention}님! 👋", ephemeral=True)

@bot.tree.command(name="상태", description="봇 및 DB 상태 점검")
async def status_cmd(inter: discord.Interaction):
    ok, info = True, "Connected"
    try:
        if engine:
            await asyncio.to_thread(lambda: engine.connect().execute(text("SELECT 1")).scalar())
            info = resolved_url.split("@")[-1].split("/")[0] if resolved_url else "Connected"
        else:
            ok = False; info = "No engine"
    except Exception as e:
        ok = False; info = f"Error: {e}"
    embed = discord.Embed(title="Bot Status", color=0x00ff00 if ok else 0xff0000)
    embed.add_field(name="Discord", value="✅ Connected", inline=True)
    embed.add_field(name="Database", value=f"{'✅' if ok else '❌'} {info}", inline=True)
    embed.add_field(name="Latency", value=f"{round(bot.latency*1000)}ms", inline=True)
    await inter.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="서버정보", description="현재 서버 정보를 보여줍니다")
async def server_info(inter: discord.Interaction):
    g = inter.guild
    embed = discord.Embed(title=f"📊 {g.name} 서버 정보", color=0x00ff00, timestamp=datetime.now())
    if g.icon: embed.set_thumbnail(url=g.icon.url)
    embed.add_field(name="서버 생성일", value=g.created_at.strftime('%Y-%m-%d'), inline=True)
    embed.add_field(name="멤버 수", value=g.member_count, inline=True)
    embed.add_field(name="채널 수", value=len(g.channels), inline=True)
    embed.add_field(name="역할 수", value=len(g.roles), inline=True)
    embed.add_field(name="서버 주인", value=g.owner.mention if g.owner else "알 수 없음", inline=True)
    await inter.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="유저정보", description="사용자 정보를 보여줍니다")
@app_commands.describe(멤버="정보를 볼 사용자 (비워두면 본인)")
async def user_info(inter: discord.Interaction, 멤버: Optional[discord.Member] = None):
    user = 멤버 or inter.user
    member = inter.guild.get_member(user.id) if inter.guild else None
    embed = discord.Embed(title=f"👤 {user.display_name}의 정보", color=0xff9900, timestamp=datetime.now())
    embed.set_thumbnail(url=user.avatar.url if user.avatar else user.default_avatar.url)
    embed.add_field(name="사용자명", value=f"{user.name}#{user.discriminator}", inline=True)
    embed.add_field(name="ID", value=user.id, inline=True)
    embed.add_field(name="계정 생성일", value=user.created_at.strftime('%Y-%m-%d'), inline=True)
    if member and member.joined_at:
        embed.add_field(name="서버 참여일", value=member.joined_at.strftime('%Y-%m-%d'), inline=True)
        embed.add_field(name="최상위 역할", value=member.top_role.mention if member.top_role else "없음", inline=True)
    await inter.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="규칙", description="서버 규칙을 보여줍니다")
async def rules(inter: discord.Interaction):
    embed = discord.Embed(
        title="📋 서버 규칙",
        description="닉언X / 타스머 언급X / 수출X / 누나 언니 형 하지마요!! 알잘딱 어길시 벤",
        color=0xff0000,
        timestamp=datetime.now()
    )
    await inter.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="이메일", description="이메일 주소를 보여줍니다")
async def email_cmd(inter: discord.Interaction):
    await inter.response.send_message('초로기: chorgi@chorogi.kr\\n매니저: nyando@chorogi.kr', ephemeral=True)

@bot.tree.command(name="도움말", description="봇의 주요 기능을 안내합니다")
async def help_cmd(inter: discord.Interaction):
    embed = discord.Embed(
        title="🤖 사용 가이드",
        description="이 봇의 주요 기능입니다.",
        color=0x00ff41,
        timestamp=datetime.now()
    )
    embed.add_field(name="📋 기본", value="`/안녕`, `/상태`, `/서버정보`, `/유저정보`, `/규칙`, `/이메일`", inline=False)
    embed.add_field(
        name="📝 대기자",
        value="`/대기자 등록|목록|제거|초기화`, `/대기자자동 채널설정|채널해제|이동채널설정|이동채널해제`",
        inline=False
    )
    embed.add_field(name="🗳️ 투표", value="`/투표생성`, `/투표종료`, `/투표결과`", inline=False)
    embed.add_field(name="🛡️ 욕설", value="`/욕설상태`, `/욕설설정`, `/욕설추가|수정|삭제|목록|리로드|초기화`, `/욕설파일추가`, `/욕설면제역할추가|삭제|목록`", inline=False)
    embed.add_field(name="🧰 보안", value="`/보안 상태|로그채널설정|로그채널해제|초대링크검열|전체멘션검열|스팸검열|스팸기준|화이트리스트보기|화이트유저추가/삭제|화이트역할추가/삭제|화이트채널추가/삭제`", inline=False)
    embed.add_field(name="📢 공지", value="`/공지`, `/공지문구설정`, `/공지문구보기`", inline=False)
    embed.add_field(name="🔔 스트림", value="`/스트림상태설정|확인|삭제`", inline=False)
    embed.add_field(name="📈 통계", value="`/이벤트집계`", inline=False)
    embed.add_field(name="🛠️ 관리자", value=f"`{PREFIX}핑`, `{PREFIX}정보`, `{PREFIX}sync`", inline=False)
    await inter.response.send_message(embed=embed, ephemeral=True)

# ---------------------- 욕설 관리: Word(.docx) 일괄 추가 ----------------------
def _extract_text_from_docx_bytes(data: bytes) -> str:
    try:
        with ZipFile(io.BytesIO(data)) as z:
            xml_bytes = z.read('word/document.xml')
        root = ET.fromstring(xml_bytes)
        ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
        texts: List[str] = []
        for t in root.findall('.//w:t', ns):
            if t.text:
                texts.append(t.text)
        return ' '.join(texts)
    except Exception:
        return ''


@bot.tree.command(name="욕설파일추가", description="Word 문서(.docx)에서 ','로 구분된 욕설을 일괄 추가합니다")
@app_commands.describe(파일=".docx 파일 (내용은 쉼표(,)로 단어 구분)", 구분자="단어 구분자, 기본 ','.")
@app_commands.default_permissions(administrator=True)
async def profanity_import_docx(inter: discord.Interaction, 파일: discord.Attachment, 구분자: str = ','):
    gid = inter.guild_id
    if not gid:
        await inter.response.send_message("❌ 길드에서만 사용할 수 있습니다.", ephemeral=True)
        return
    if not 파일 or not isinstance(파일, discord.Attachment):
        await inter.response.send_message("❌ 파일을 첨부해 주세요.", ephemeral=True)
        return
    name = (파일.filename or '').lower()
    if not name.endswith('.docx'):
        await inter.response.send_message("❌ .docx 형식의 Word 문서만 지원합니다.", ephemeral=True)
        return
    try:
        await inter.response.defer(ephemeral=True, thinking=True)
    except Exception:
        pass
    try:
        data = await 파일.read()
    except Exception as e:
        await inter.followup.send(f"❌ 파일을 불러오지 못했습니다: {e}", ephemeral=True)
        return

    text = _extract_text_from_docx_bytes(data)
    if not text:
        await inter.followup.send("❌ 문서에서 텍스트를 추출하지 못했습니다. 문서 내용을 확인해주세요.", ephemeral=True)
        return

    sep = 구분자 or ','
    raw_items = [x.strip() for x in text.split(sep)]
    # 순서 유지하며 공백/중복 제거
    items: List[str] = []
    seen = set()
    for it in raw_items:
        if not it:
            continue
        if it in seen:
            continue
        seen.add(it)
        items.append(it)

    added = 0
    skipped = 0
    errors = 0
    for w in items:
        try:
            if bw_exists(gid, w):
                skipped += 1
            else:
                bw_add(gid, w, added_by=getattr(inter.user, 'id', None))
                added += 1
        except Exception:
            errors += 1

    try:
        await _load_guild_cache(gid)
    except Exception:
        pass

    await inter.followup.send(
        f"📥 처리 완료: 총 {len(items)}개 • 추가 {added} • 중복 {skipped} • 오류 {errors}",
        ephemeral=True
    )

# ---------------------- 이벤트 집계 ----------------------
@bot.tree.command(name="이벤트집계", description="서버의 주요 이벤트 집계 현황을 보여줍니다")
@app_commands.describe(기간="집계 기간: 기본 7일")
@app_commands.choices(기간=[
    app_commands.Choice(name="오늘", value="today"),
    app_commands.Choice(name="7일", value="7d"),
    app_commands.Choice(name="30일", value="30d"),
    app_commands.Choice(name="전체", value="all"),
])
async def event_stats_cmd(inter: discord.Interaction, 기간: app_commands.Choice[str] = None):
    gid = inter.guild_id
    if not gid:
        await inter.response.send_message("❌ 길드에서만 사용할 수 있습니다.", ephemeral=True); return
    period = (기간.value if 기간 else "7d")
    days_lookup = {"today": 1, "7d": 7, "30d": 30}
    days = days_lookup.get(period, 7)

    try:
        daily = event_sum_days(gid, days) if period != "all" else {}
        total = event_sum_total(gid)
    except Exception as e:
        await inter.response.send_message(f"❌ 집계 조회 중 오류: {e}", ephemeral=True); return

    # 표시할 키 목록 고정 순서
    ordered_keys = [
        "message_total",
        "blocked_everyone",
        "blocked_invite",
        "blocked_spam",
        "profanity_delete",
        "profanity_warn",
        "member_join",
        "member_leave",
        "auto_add_waitlist",
    ]

    title_period = {
        "today": "오늘",
        "7d": "최근 7일",
        "30d": "최근 30일",
        "all": "전체",
    }.get(period, "최근 7일")

    embed = discord.Embed(title=f"📈 이벤트 집계 — {title_period}", color=0x00b8d4, timestamp=datetime.now())
    lines = []
    for k in ordered_keys:
        label = EVENT_LABELS.get(k, k)
        if period == "all":
            t = int(total.get(k, 0))
            lines.append(f"• {label}: 총 {t}건")
        else:
            d = int(daily.get(k, 0))
            t = int(total.get(k, 0))
            lines.append(f"• {label}: {d}건 (총 {t}건)")

    # 다른 키가 DB에 있을 수 있어 합계 열을 추가
    if period != "all":
        # 표시되지 않은 기타 키 합산
        shown = set(ordered_keys)
        other_daily = sum(v for kk, v in daily.items() if kk not in shown)
        other_total = sum(v for kk, v in total.items() if kk not in shown)
        if other_daily or other_total:
            lines.append(f"• 기타: {other_daily}건 (총 {other_total}건)")

    embed.description = "\n".join(lines) if lines else "데이터가 없습니다."
    await inter.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="반응집계", description="사용자의 반응(이모지) 수를 집계합니다")
@app_commands.describe(사용자="조회할 사용자 (미지정 시 본인)", 기간="기간: 기본 7일")
@app_commands.choices(기간=[
    app_commands.Choice(name="오늘", value="today"),
    app_commands.Choice(name="7일", value="7d"),
    app_commands.Choice(name="30일", value="30d"),
    app_commands.Choice(name="전체", value="all"),
])
async def reaction_stats_cmd(inter: discord.Interaction, 사용자: Optional[discord.Member] = None, 기간: app_commands.Choice[str] = None):
    gid = inter.guild_id
    if not gid:
        await inter.response.send_message("❌ 길드에서만 사용할 수 있습니다.", ephemeral=True); return
    target = 사용자 or inter.user
    period = (기간.value if 기간 else "7d")
    days_lookup = {"today": 1, "7d": 7, "30d": 30}
    days = days_lookup.get(period, 7)

    try:
        d = reaction_sum_days(int(gid), int(target.id), days) if period != "all" else None
        t = reaction_sum_total(int(gid), int(target.id))
    except Exception as e:
        await inter.response.send_message(f"❌ 반응 집계 조회 오류: {e}", ephemeral=True); return

    title_period = {
        "today": "오늘",
        "7d": "최근 7일",
        "30d": "최근 30일",
        "all": "전체",
    }.get(period, "최근 7일")

    embed = discord.Embed(title=f"👍 반응 집계 — {target.display_name}", color=0xffab00, timestamp=datetime.now())
    if period == "all":
        embed.description = f"• 기간: {title_period}\n• 총 반응 수: {t}건"
    else:
        embed.description = f"• 기간: {title_period}\n• 기간 내 반응 수: {d or 0}건\n• 총 반응 수: {t}건"
    await inter.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="반응추첨", description="반응 집계로 랜덤 N명 추첨합니다")
@app_commands.describe(인원="추첨 인원 (기본 1)", 방식="선정 방식(가중/균등)", 기간="기본 7일", 중복허용="같은 사람이 여러 번 뽑힐 수 있음")
@app_commands.choices(방식=[
    app_commands.Choice(name="가중(반응수 비례)", value="weighted"),
    app_commands.Choice(name="균등(참여자 동일확률)", value="uniform"),
])
@app_commands.choices(기간=[
    app_commands.Choice(name="오늘", value="today"),
    app_commands.Choice(name="7일", value="7d"),
    app_commands.Choice(name="30일", value="30d"),
    app_commands.Choice(name="전체", value="all"),
])
async def reaction_raffle_cmd(
    inter: discord.Interaction,
    인원: app_commands.Range[int, 1, 50] = 1,
    방식: app_commands.Choice[str] = None,
    기간: app_commands.Choice[str] = None,
    중복허용: bool = False,
):
    gid = inter.guild_id
    if not gid:
        await inter.response.send_message("❌ 길드에서만 사용할 수 있습니다.", ephemeral=True); return
    method = (방식.value if 방식 else "weighted")
    period = (기간.value if 기간 else "7d")
    days_lookup = {"today": 1, "7d": 7, "30d": 30}

    # 참가자 집계
    if period == "all":
        ranks_raw = reaction_rank_total(int(gid))
    else:
        days = days_lookup.get(period, 7)
        ranks_raw = reaction_rank_days(int(gid), days)

    ranks = _filter_current_members(inter.guild, ranks_raw)
    if not ranks:
        await inter.response.send_message("❌ 기간 내 반응한 사용자가 없습니다.", ephemeral=True); return

    user_ids = [uid for uid, _ in ranks]
    weights = [c for _, c in ranks]

    # 선정 로직
    winners: List[int] = []
    if 중복허용:
        if method == "uniform":
            winners = random.choices(user_ids, k=인원)
        else:
            winners = random.choices(user_ids, weights=weights, k=인원)
    else:
        # 중복 불가
        if method == "uniform":
            if 인원 > len(user_ids):
                인원 = len(user_ids)
            winners = random.sample(user_ids, k=인원)
        else:
            # 가중치 비복원 추출: 반복 선택 후 제거
            pool_ids = user_ids[:]
            pool_wts = weights[:]
            n = min(인원, len(pool_ids))
            for _ in range(n):
                pick = random.choices(pool_ids, weights=pool_wts, k=1)[0]
                winners.append(pick)
                i = pool_ids.index(pick)
                del pool_ids[i]
                del pool_wts[i]

    # 표시용 멘션 + 점수
    def mention_of(uid: int) -> str:
        m = inter.guild.get_member(uid) if inter.guild else None
        return m.mention if m else f"<@{uid}>"

    score_map = {uid: c for uid, c in ranks}
    title_period = {
        "today": "오늘",
        "7d": "최근 7일",
        "30d": "최근 30일",
        "all": "전체",
    }.get(period, "최근 7일")
    method_label = "가중(반응수 비례)" if method == "weighted" else "균등(동일확률)"
    lines = []
    for i, uid in enumerate(winners, 1):
        lines.append(f"{i}. {mention_of(uid)} — 점수 {score_map.get(uid, 0)}")

    embed = discord.Embed(title="🎲 반응 추첨 결과", color=0x4caf50, timestamp=datetime.now())
    embed.add_field(name="기간", value=title_period, inline=True)
    embed.add_field(name="방식", value=method_label + ("/중복" if 중복허용 else "/비중복"), inline=True)
    embed.add_field(name="인원", value=str(len(winners)), inline=True)
    embed.description = "\n".join(lines) if lines else "(선정 결과가 없습니다)"
    await inter.response.send_message(embed=embed, ephemeral=False)

@bot.tree.command(name="메시지반응집계", description="특정 메시지에 반응한 사용자 집계")
@app_commands.describe(메시지="메시지 ID(snowflake)", 이모지="특정 이모지로 필터링(선택)", 상위="표시할 상위 인원수(기본 20)")
async def message_reaction_stats_cmd(inter: discord.Interaction, 메시지: str, 이모지: Optional[str] = None, 상위: app_commands.Range[int, 1, 50] = 20):
    gid = inter.guild_id
    if not gid:
        await inter.response.send_message("❌ 길드에서만 사용할 수 있습니다.", ephemeral=True); return
    try:
        mid = int(메시지)
    except ValueError:
        await inter.response.send_message("❌ 메시지 ID가 올바르지 않습니다.", ephemeral=True); return
    emoji_key_in = parse_emoji_key(이모지) if 이모지 else ""
    ranks_raw = react_msg_emoji_rank(int(gid), mid, emoji_key_in) if emoji_key_in else react_msg_rank(int(gid), mid)
    ranks = _filter_current_members(inter.guild, ranks_raw)
    if not ranks:
        await inter.response.send_message("데이터가 없습니다. 이 메시지에 반응 사용자가 없거나, 봇이 관찰하기 전의 반응일 수 있습니다.", ephemeral=True); return

    lines = []
    for i, (uid, cnt) in enumerate(ranks[:상위], 1):
        m = inter.guild.get_member(uid) if inter.guild else None
        mention = m.mention if m else f"<@{uid}>"
        lines.append(f"{i}. {mention} — {cnt}회")
    more = len(ranks) - 상위
    desc = "\n".join(lines)
    if more > 0:
        desc += f"\n… 외 {more}명"
    embed = discord.Embed(title="📌 메시지 반응 집계", description=desc, color=0x42a5f5, timestamp=datetime.now())
    embed.add_field(name="메시지 ID", value=str(mid), inline=True)
    embed.add_field(name="참여자 수", value=str(len(ranks)), inline=True)
    if emoji_key_in:
        embed.add_field(name="이모지", value=(이모지 or emoji_key_in), inline=True)
    await inter.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="메시지반응추첨", description="특정 메시지에 반응한 사람 중 추첨")
@app_commands.describe(메시지="메시지 ID(snowflake)", 이모지="특정 이모지로 필터링(선택)", 인원="추첨 인원(기본 1)", 방식="가중(반응수 비례)/균등", 중복허용="같은 사람 중복 당첨 허용")
@app_commands.choices(방식=[
    app_commands.Choice(name="가중(반응수 비례)", value="weighted"),
    app_commands.Choice(name="균등(참여자 동일확률)", value="uniform"),
])
async def message_reaction_raffle_cmd(
    inter: discord.Interaction,
    메시지: str,
    이모지: Optional[str] = None,
    인원: app_commands.Range[int, 1, 50] = 1,
    방식: app_commands.Choice[str] = None,
    중복허용: bool = False,
):
    gid = inter.guild_id
    if not gid:
        await inter.response.send_message("❌ 길드에서만 사용할 수 있습니다.", ephemeral=True); return
    try:
        mid = int(메시지)
    except ValueError:
        await inter.response.send_message("❌ 메시지 ID가 올바르지 않습니다.", ephemeral=True); return
    method = (방식.value if 방식 else "weighted")
    emoji_key_in = parse_emoji_key(이모지) if 이모지 else ""
    ranks_raw = react_msg_emoji_rank(int(gid), mid, emoji_key_in) if emoji_key_in else react_msg_rank(int(gid), mid)
    ranks = _filter_current_members(inter.guild, ranks_raw)
    if not ranks:
        await inter.response.send_message("❌ 반응 참여자가 없습니다.", ephemeral=True); return
    user_ids = [uid for uid, _ in ranks]
    weights = [c for _, c in ranks]

    winners: List[int] = []
    if 중복허용:
        if method == "uniform":
            winners = random.choices(user_ids, k=인원)
        else:
            winners = random.choices(user_ids, weights=weights, k=인원)
    else:
        if method == "uniform":
            인원 = min(인원, len(user_ids))
            winners = random.sample(user_ids, k=인원)
        else:
            pool_ids = user_ids[:]
            pool_wts = weights[:]
            n = min(인원, len(pool_ids))
            for _ in range(n):
                pick = random.choices(pool_ids, weights=pool_wts, k=1)[0]
                winners.append(pick)
                i = pool_ids.index(pick)
                del pool_ids[i]
                del pool_wts[i]

    def mention_of(uid: int) -> str:
        m = inter.guild.get_member(uid) if inter.guild else None
        return m.mention if m else f"<@{uid}>"

    score_map = {uid: c for uid, c in ranks}
    lines = [f"{i}. {mention_of(uid)} — {score_map.get(uid, 0)}회" for i, uid in enumerate(winners, 1)]
    embed = discord.Embed(title="🎯 메시지 반응 추첨 결과", description="\n".join(lines) or "(없음)", color=0x66bb6a, timestamp=datetime.now())
    embed.add_field(name="메시지 ID", value=str(mid), inline=True)
    embed.add_field(name="방식", value=("가중" if method=="weighted" else "균등") + ("/중복" if 중복허용 else "/비중복"), inline=True)
    embed.add_field(name="인원", value=str(len(winners)), inline=True)
    if emoji_key_in:
        embed.add_field(name="이모지", value=(이모지 or emoji_key_in), inline=True)
    await inter.response.send_message(embed=embed, ephemeral=True)

# 체크(✅) 반응을 한 사용자 중에서 균등 확률로 N명 선정하는 간편 명령
@bot.tree.command(name="체크추첨", description="✅ 반응한 사람 중 랜덤 N명 추첨")
@app_commands.describe(메시지="메시지 ID(snowflake)", 인원="추첨 인원(기본 1)", 중복허용="같은 사람 중복 당첨 허용")
async def check_raffle_cmd(
    inter: discord.Interaction,
    메시지: str,
    인원: app_commands.Range[int, 1, 50] = 1,
    중복허용: bool = False,
):
    gid = inter.guild_id
    if not gid:
        await inter.response.send_message("❌ 길드에서만 사용할 수 있습니다.", ephemeral=True); return
    try:
        mid = int(메시지)
    except ValueError:
        await inter.response.send_message("❌ 메시지 ID가 올바르지 않습니다.", ephemeral=True); return

    # ✅ 유니코드 이모지 키 지정
    emoji_key_in = parse_emoji_key("✅")
    ranks_raw = react_msg_emoji_rank(int(gid), mid, emoji_key_in)
    ranks = _filter_current_members(inter.guild, ranks_raw)
    if not ranks:
        await inter.response.send_message("❌ ✅ 반응 참여자가 없습니다.", ephemeral=True); return

    # 관리자 권한 보유자 제외
    elig_ids: List[int] = []
    gm = inter.guild.get_member if inter.guild else (lambda _x: None)
    for uid, _ in ranks:
        m = gm(uid)
        if not m:
            continue
        if getattr(m.guild_permissions, "administrator", False):
            continue
        elig_ids.append(uid)

    if not elig_ids:
        await inter.response.send_message("❌ 관리자 제외 후 추첨 대상이 없습니다.", ephemeral=True); return

    if 중복허용:
        winners = random.choices(elig_ids, k=인원)
    else:
        인원 = min(인원, len(elig_ids))
        winners = random.sample(elig_ids, k=인원)

    def mention_of(uid: int) -> str:
        m = inter.guild.get_member(uid) if inter.guild else None
        return m.mention if m else f"<@{uid}>"

    # winners = [user_id1, user_id2, ...] 가정
    lines = [
        f"{i}. <@{uid}>"  # Discord mention은 <@user_id> 형태
        for i, uid in enumerate(winners, start=1)
    ]

    embed = discord.Embed(
        title="✅ 체크 반응 추첨 결과",
        description="\n".join(lines) if lines else "(없음)",
        color=0x2e7d32,
        timestamp=datetime.now()
    )

    await inter.response.send_message(embed=embed, ephemeral=False)

# ---------------------- 음성 이동/조회 ----------------------
@bot.tree.command(name="이동", description="대기자 목록 순으로 음성 채널을 이동시킵니다")
async def move_user(inter: discord.Interaction):
    if not inter.user.guild_permissions.move_members:
        await inter.response.send_message('❌ 멤버 이동 권한이 필요합니다!', ephemeral=True); return
    guild = inter.guild
    if not guild:
        await inter.response.send_message('❌ 길드 정보가 없습니다.', ephemeral=True); return
    source_channel_id = aac_get(inter.guild_id)
    if not source_channel_id:
        await inter.response.send_message('⚠️ 먼저 `/대기자자동 채널설정`으로 대기 채널을 설정해주세요.', ephemeral=True); return
    source_channel = guild.get_channel(int(source_channel_id))
    if not isinstance(source_channel, discord.VoiceChannel):
        await inter.response.send_message('❌ 설정된 대기 채널을 찾을 수 없습니다.', ephemeral=True); return
    target_channel_id = _get_auto_move_target_channel_id(inter.guild_id)
    if not target_channel_id:
        await inter.response.send_message('⚠️ `/대기자자동 이동채널설정`으로 이동시킬 음성 채널을 먼저 지정해주세요.', ephemeral=True); return
    target_channel = guild.get_channel(int(target_channel_id))
    if not isinstance(target_channel, discord.VoiceChannel):
        await inter.response.send_message('❌ 지정된 이동 대상 채널을 찾을 수 없습니다. `/대기자자동 이동채널설정`을 다시 설정해주세요.', ephemeral=True); return

    wait_list = wl_list(inter.guild_id)
    if not wait_list:
        await inter.response.send_message("ℹ️ 대기자 목록이 비어 있습니다.", ephemeral=True); return

    moved_member: Optional[discord.Member] = None
    for entry in wait_list:
        uid = int(entry.get("user_id", 0) or 0)
        member = guild.get_member(uid)
        if not member or not member.voice or not member.voice.channel:
            continue
        if member.voice.channel.id != int(source_channel_id):
            continue
        try:
            await member.move_to(target_channel)
            wl_remove(inter.guild_id, member.id)
            moved_member = member
            break
        except discord.Forbidden:
            await inter.response.send_message('❌ 해당 채널로 사용자를 이동시킬 권한이 없습니다!', ephemeral=True)
            return
        except discord.HTTPException as e:
            await inter.response.send_message(f'❌ 이동 중 오류가 발생했습니다: {e}', ephemeral=True)
            return

    if not moved_member:
        await inter.response.send_message("⚠️ 대기자 목록에 있지만 이동 가능한 사용자가 없습니다. 대기 채널 접속 여부를 확인해주세요.", ephemeral=True); return

    await inter.response.send_message(
        f'✅ {moved_member.mention}님을 {source_channel.mention}에서 {target_channel.mention}로 이동시켰습니다!',
        ephemeral=True
    )

@bot.tree.command(name="음성채널목록", description="서버의 모든 음성 채널 목록을 보여줍니다")
async def voice_channels(inter: discord.Interaction):
    guild = inter.guild
    vcs = [c for c in guild.channels if isinstance(c, discord.VoiceChannel)]
    if not vcs:
        await inter.response.send_message('❌ 음성 채널이 없습니다!', ephemeral=True); return
    embed = discord.Embed(title=f'🔊 {guild.name}의 음성 채널 목록', color=0x00ff00, timestamp=datetime.now())
    for ch in vcs:
        member_count = len(ch.members)
        names = ', '.join([m.display_name for m in ch.members[:5]]) or '비어있음'
        if member_count > 5: names += f' 외 {member_count - 5}명'
        embed.add_field(name=f'{ch.name} ({member_count}명)', value=names, inline=False)
    await inter.response.send_message(embed=embed, ephemeral=True)

# ---------------------- 대기자 그룹 ----------------------
대기자 = app_commands.Group(name="대기자", description="대기자 관리")

@대기자.command(name="등록", description="대기자 목록에 추가합니다")
@app_commands.describe(멤버="추가할 멤버 (비워두면 본인)")
async def 대기자_등록(inter: discord.Interaction, 멤버: Optional[discord.Member]=None):
    target = 멤버 or inter.user
    ok = wl_add(inter.guild_id, target.id, target.display_name)
    await inter.response.send_message("✅ 등록되었습니다." if ok else "ℹ️ 이미 등록되어 있습니다.", ephemeral=True)

@대기자.command(name="목록", description="대기자 목록을 보여줍니다")
async def 대기자_목록(inter: discord.Interaction):
    rows = wl_list(inter.guild_id)
    if not rows:
        await inter.response.send_message("목록이 비어 있습니다.", ephemeral=True); return
    lines = [f"- <@{r['user_id']}> • {r['timestamp']:%m-%d %H:%M}" if isinstance(r['timestamp'], datetime) else f"- <@{r['user_id']}>"
             for r in rows]
    await inter.response.send_message("\\n".join(lines), ephemeral=True)

@대기자.command(name="제거", description="대기자에서 제거합니다")
@app_commands.describe(멤버="제거할 멤버")
async def 대기자_제거(inter: discord.Interaction, 멤버: discord.Member):
    cnt = wl_remove(inter.guild_id, 멤버.id)
    await inter.response.send_message("✅ 제거되었습니다." if cnt>0 else "대상 없음.", ephemeral=True)

@대기자.command(name="초기화", description="대기자 목록을 비웁니다")
@commands.has_permissions(manage_guild=True)
async def 대기자_초기화(inter: discord.Interaction):
    cnt = wl_clear(inter.guild_id)
    await inter.response.send_message(f"🧹 초기화: {cnt}명 제거", ephemeral=True)

bot.tree.add_command(대기자)

# 자동추가 채널
자동 = app_commands.Group(name="대기자자동", description="대기자 자동 추가 채널 설정")

@자동.command(name="채널설정", description="특정 음성 채널에 접속 시 자동으로 대기자에 추가")
@app_commands.describe(채널="감시할 음성 채널")
async def 자동_채널설정(inter: discord.Interaction, 채널: discord.VoiceChannel):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    aac_set(inter.guild_id, 채널.id)
    await inter.response.send_message(f"✅ 자동 추가 채널 설정: {채널.mention}", ephemeral=True)

@자동.command(name="채널해제", description="자동 추가 채널 설정을 해제")
async def 자동_채널해제(inter: discord.Interaction):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    cnt = aac_remove(inter.guild_id)
    await inter.response.send_message("✅ 해제되었습니다." if cnt>0 else "설정이 존재하지 않습니다.", ephemeral=True)

@자동.command(name="이동채널설정", description="대기자를 이동시킬 목적 음성 채널을 지정")
@app_commands.describe(채널="이동시킬 대상 음성 채널")
async def 자동_이동채널설정(inter: discord.Interaction, 채널: discord.VoiceChannel):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    _set_auto_move_target_channel_id(inter.guild_id, 채널.id)
    await inter.response.send_message(f"✅ 이동 대상 채널이 {채널.mention}으로 설정되었습니다.", ephemeral=True)

@자동.command(name="이동채널해제", description="이동 대상 채널 설정을 초기화")
async def 자동_이동채널해제(inter: discord.Interaction):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    removed = _clear_auto_move_target_channel_id(inter.guild_id)
    await inter.response.send_message(
        "✅ 이동 대상 채널 설정이 초기화되어 기본 채널이 사용됩니다."
        if removed else "ℹ️ 이미 기본 이동 채널 설정만 사용 중입니다.",
        ephemeral=True
    )

bot.tree.add_command(자동)

# ---------------------- 자동 역할 ----------------------
자동역할 = app_commands.Group(name="자동역할", description="신규 입장 시 자동 역할 부여")

@자동역할.command(name="보기", description="현재 설정된 자동 역할(여러 개 가능)을 보여줍니다")
async def autorole_show(inter: discord.Interaction):
    ids = ar_items(inter.guild_id)
    if not ids:
        # 레거시 단일 설정 호환
        rid = ar_get(inter.guild_id)
        if rid:
            ids = [rid]
    if not ids:
        await inter.response.send_message("(미설정)", ephemeral=True); return
    rolestr = ", ".join(
        (inter.guild.get_role(i).mention if inter.guild and inter.guild.get_role(i) else f"<@&{i}>")
        for i in ids
    )
    await inter.response.send_message(rolestr, ephemeral=True)

@자동역할.command(name="설정", description="자동 역할을 단일 역할로 재설정(기존 목록 초기화)")
@app_commands.describe(역할="입장 시 부여할 역할")
async def autorole_set(inter: discord.Interaction, 역할: discord.Role):
    if not inter.user.guild_permissions.manage_roles:
        await inter.response.send_message("역할 관리 권한이 필요합니다.", ephemeral=True); return
    ar_clear(inter.guild_id)
    ar_items_clear(inter.guild_id)
    ar_item_add(inter.guild_id, 역할.id)
    await inter.response.send_message(f"✅ 자동 역할이 {역할.mention} 하나로 설정되었습니다.", ephemeral=True)

@자동역할.command(name="해제", description="자동 역할 설정을 모두 해제합니다")
async def autorole_unset(inter: discord.Interaction):
    if not inter.user.guild_permissions.manage_roles:
        await inter.response.send_message("역할 관리 권한이 필요합니다.", ephemeral=True); return
    cnt1 = ar_clear(inter.guild_id)
    cnt2 = ar_items_clear(inter.guild_id)
    await inter.response.send_message("✅ 전체 해제되었습니다." if (cnt1+cnt2)>0 else "설정이 존재하지 않습니다.", ephemeral=True)

@자동역할.command(name="추가", description="자동 역할 목록에 역할을 추가합니다")
@app_commands.describe(역할="추가할 역할")
async def autorole_add(inter: discord.Interaction, 역할: discord.Role):
    if not inter.user.guild_permissions.manage_roles:
        await inter.response.send_message("역할 관리 권한이 필요합니다.", ephemeral=True); return
    ok = ar_item_add(inter.guild_id, 역할.id)
    await inter.response.send_message("✅ 추가되었습니다." if ok else "이미 목록에 있습니다.", ephemeral=True)

@자동역할.command(name="삭제", description="자동 역할 목록에서 역할을 제거합니다")
@app_commands.describe(역할="제거할 역할")
async def autorole_remove(inter: discord.Interaction, 역할: discord.Role):
    if not inter.user.guild_permissions.manage_roles:
        await inter.response.send_message("역할 관리 권한이 필요합니다.", ephemeral=True); return
    ok = ar_item_del(inter.guild_id, 역할.id)
    await inter.response.send_message("✅ 제거되었습니다." if ok else "대상 없음.", ephemeral=True)

@자동역할.command(name="목록", description="자동 역할 목록을 순서대로 표시합니다")
async def autorole_list(inter: discord.Interaction):
    ids = ar_items(inter.guild_id)
    if not ids:
        await inter.response.send_message("(비어 있음)", ephemeral=True); return
    lines = []
    for i, rid in enumerate(ids, start=1):
        r = inter.guild.get_role(rid) if inter.guild else None
        lines.append(f"{i}. {r.mention if r else f'<@&{rid}>'}")
    await inter.response.send_message("\n".join(lines), ephemeral=True)

@자동역할.command(name="순서", description="역할의 적용 순서를 설정합니다(1부터)")
@app_commands.describe(역할="대상 역할", 위치="새 순서(1부터)")
async def autorole_reorder(inter: discord.Interaction, 역할: discord.Role, 위치: int):
    if not inter.user.guild_permissions.manage_roles:
        await inter.response.send_message("역할 관리 권한이 필요합니다.", ephemeral=True); return
    ok = ar_item_setpos(inter.guild_id, 역할.id, 위치)
    await inter.response.send_message("✅ 순서가 변경되었습니다." if ok else "대상 역할이 목록에 없습니다.", ephemeral=True)

@자동역할.command(name="조건보기", description="특정 역할의 자동 부여 조건을 확인합니다")
@app_commands.describe(역할="대상 역할")
async def autorole_cond_show(inter: discord.Interaction, 역할: discord.Role):
    # 항목이 없다면 기본값
    rows = [r for r in ar_item_rows(inter.guild_id) if int(getattr(r, 'role_id', 0)) == 역할.id]
    it = rows[0] if rows else None
    tgt_map = {0: '전체', 1: '봇만', 2: '사람만'}
    target = tgt_map.get(int(getattr(it, 'target', 0) if it else 0), '전체')
    booster = '예' if (getattr(it, 'booster_only', False) if it else False) else '아니오'
    acc = int(getattr(it, 'min_account_days', 0) if it else 0)
    jnd = int(getattr(it, 'min_join_days', 0) if it else 0)
    embed = discord.Embed(title=f"⚙️ 자동역할 조건 — {역할.name}", color=0x90caf9, timestamp=datetime.now())
    embed.add_field(name="대상", value=target, inline=True)
    embed.add_field(name="부스터 전용", value=booster, inline=True)
    embed.add_field(name="계정 경과일", value=f"{acc}일", inline=True)
    embed.add_field(name="가입 경과일", value=f"{jnd}일", inline=True)
    await inter.response.send_message(embed=embed, ephemeral=True)

@자동역할.command(name="조건설정", description="역할의 자동 부여 조건을 설정합니다")
@app_commands.describe(역할="대상 역할", 대상="전체/봇만/사람만", 부스터전용="서버 부스터에게만 부여", 계정일수="계정 생성 후 최소 일수", 가입일수="서버 가입 후 최소 일수")
@app_commands.choices(대상=[
    app_commands.Choice(name="전체", value=0),
    app_commands.Choice(name="봇만", value=1),
    app_commands.Choice(name="사람만", value=2),
])
async def autorole_cond_set(
    inter: discord.Interaction,
    역할: discord.Role,
    대상: Optional[app_commands.Choice[int]] = None,
    부스터전용: Optional[bool] = None,
    계정일수: Optional[int] = None,
    가입일수: Optional[int] = None,
):
    if not inter.user.guild_permissions.manage_roles:
        await inter.response.send_message("역할 관리 권한이 필요합니다.", ephemeral=True); return
    # 항목 없으면 추가부터
    if not any(r for r in ar_item_rows(inter.guild_id) if int(getattr(r, 'role_id', 0)) == 역할.id):
        ar_item_add(inter.guild_id, 역할.id)
    ok = ar_item_update(
        inter.guild_id,
        역할.id,
        target=(대상.value if 대상 is not None else None),
        booster_only=부스터전용,
        min_account_days=계정일수,
        min_join_days=가입일수,
    )
    await inter.response.send_message("✅ 조건이 저장되었습니다." if ok else "❌ 저장 실패", ephemeral=True)

@자동역할.command(name="조건초기화", description="역할의 자동 부여 조건을 기본값으로 되돌립니다")
@app_commands.describe(역할="대상 역할")
async def autorole_cond_reset(inter: discord.Interaction, 역할: discord.Role):
    if not inter.user.guild_permissions.manage_roles:
        await inter.response.send_message("역할 관리 권한이 필요합니다.", ephemeral=True); return
    # 기본값으로 overwrite
    if not any(r for r in ar_item_rows(inter.guild_id) if int(getattr(r, 'role_id', 0)) == 역할.id):
        ar_item_add(inter.guild_id, 역할.id)
    ar_item_update(inter.guild_id, 역할.id, target=0, booster_only=False, min_account_days=0, min_join_days=0)
    await inter.response.send_message("✅ 기본값으로 초기화되었습니다.", ephemeral=True)

@자동역할.command(name="적용", description="현재 조건에 맞는 역할을 대상 사용자에게 즉시 부여합니다")
@app_commands.describe(사용자="대상 사용자(비워두면 본인)")
async def autorole_apply(inter: discord.Interaction, 사용자: Optional[discord.Member] = None):
    member = 사용자 or inter.user
    items = ar_item_rows(inter.guild_id)
    if not items:
        await inter.response.send_message("설정된 자동 역할이 없습니다.", ephemeral=True); return
    me = getattr(inter.guild, 'me', None)
    to_add: List[discord.Role] = []
    for it in items:
        r = inter.guild.get_role(int(it.role_id)) if it and getattr(it, 'role_id', None) else None
        if not r:
            continue
        if not _autorole_match(member, it):
            continue
        try:
            if me and not (r < me.top_role):
                continue
        except Exception:
            pass
        if getattr(r, 'managed', False):
            continue
        if any(rr.id == r.id for rr in getattr(member, 'roles', [])):
            continue
        to_add.append(r)
    if not to_add:
        await inter.response.send_message("부여할 역할이 없습니다.", ephemeral=True); return
    try:
        await member.add_roles(*to_add, reason="자동 역할(수동 적용)")
        await inter.response.send_message("✅ 적용되었습니다.", ephemeral=True)
    except discord.Forbidden:
        await inter.response.send_message("❌ 권한 부족으로 실패했습니다.", ephemeral=True)
    except Exception as e:
        await inter.response.send_message(f"❌ 오류: {e}", ephemeral=True)

bot.tree.add_command(자동역할)

# ---------------------- 랭크/레벨 (MEE6 스타일) ----------------------
def _progress_bar(cur: int, need: int, length: int = 18) -> str:
    try:
        ratio = 0.0 if need <= 0 else max(0.0, min(1.0, cur / need))
    except Exception:
        ratio = 0.0
    filled = int(round(length * ratio))
    return "█" * filled + "─" * (length - filled)

@bot.tree.command(name="랭크", description="사용자 랭크/레벨을 보여줍니다 (MEE6 스타일)")
@app_commands.describe(사용자="조회할 사용자(없으면 본인)")
async def rank_command(inter: discord.Interaction, 사용자: Optional[discord.Member] = None):
    if not inter.guild_id:
        await inter.response.send_message("서버 내에서만 사용할 수 있습니다.", ephemeral=True); return
    member = 사용자 or inter.user
    total = xp_get_total(inter.guild_id, member.id)
    lvl, cur_in_level, need_next = level_from_total_xp(total)
    rank_idx, total_users, _ = xp_rank(inter.guild_id, member.id)
    bar = _progress_bar(cur_in_level, need_next)
    embed = discord.Embed(title="📈 랭크", color=0x9c27b0, timestamp=datetime.now())
    # Use display_avatar which always resolves to a valid avatar (custom or default)
    embed.set_author(name=str(member), icon_url=member.display_avatar.url)
    embed.add_field(name="레벨", value=str(lvl), inline=True)
    embed.add_field(name="랭크", value=(f"#{rank_idx} / {total_users}" if total_users else "N/A"), inline=True)
    embed.add_field(name="총 XP", value=str(total), inline=True)
    embed.add_field(name="진행도", value=f"{bar} ({cur_in_level}/{need_next})", inline=False)
    await inter.response.send_message(embed=embed, ephemeral=False)

@bot.tree.command(name="리더보드", description="서버 XP 리더보드")
@app_commands.describe(상위="표시할 인원 수 (기본 10)")
async def leaderboard_command(inter: discord.Interaction, 상위: app_commands.Range[int, 1, 25] = 10):
    if not inter.guild_id:
        await inter.response.send_message("서버 내에서만 사용할 수 있습니다.", ephemeral=True); return
    top = xp_top(inter.guild_id, limit=상위)
    if not top:
        await inter.response.send_message("데이터가 없습니다.", ephemeral=True); return
    lines = []
    gm = inter.guild.get_member if inter.guild else (lambda _x: None)
    for i, (uid, xp_val) in enumerate(top, 1):
        m = gm(uid)
        name = m.mention if m else f"<@{uid}>"
        lvl, cur, need = level_from_total_xp(xp_val)
        lines.append(f"{i}. {name} — Lv.{lvl} ({xp_val} XP)")
    embed = discord.Embed(title="🏆 XP 리더보드", description="\n".join(lines), color=0xffc107, timestamp=datetime.now())
    await inter.response.send_message(embed=embed, ephemeral=False)

# 프리픽스 버전 (선택)
@bot.command(name="rank")
async def rank_prefix(ctx: commands.Context, member: Optional[discord.Member] = None):
    if not ctx.guild:
        return
    target = member or ctx.author
    total = xp_get_total(ctx.guild.id, target.id)
    lvl, cur_in_level, need_next = level_from_total_xp(total)
    rank_idx, total_users, _ = xp_rank(ctx.guild.id, target.id)
    bar = _progress_bar(cur_in_level, need_next)
    embed = discord.Embed(title="📈 랭크", color=0x9c27b0)
    # Use display_avatar for broader compatibility across discord.py versions
    embed.set_author(name=str(target), icon_url=target.display_avatar.url)
    embed.add_field(name="레벨", value=str(lvl), inline=True)
    embed.add_field(name="랭크", value=(f"#{rank_idx} / {total_users}" if total_users else "N/A"), inline=True)
    embed.add_field(name="총 XP", value=str(total), inline=True)
    embed.add_field(name="진행도", value=f"{bar} ({cur_in_level}/{need_next})", inline=False)
    await ctx.send(embed=embed)

@bot.command(name="leaderboard", aliases=["lb"]) 
async def leaderboard_prefix(ctx: commands.Context, limit: int = 10):
    if not ctx.guild:
        return
    limit = max(1, min(25, int(limit)))
    top = xp_top(ctx.guild.id, limit=limit)
    if not top:
        await ctx.send("데이터가 없습니다.")
        return
    lines = []
    for i, (uid, xp_val) in enumerate(top, 1):
        m = ctx.guild.get_member(uid)
        name = m.mention if m else f"<@{uid}>"
        lvl, _, _ = level_from_total_xp(xp_val)
        lines.append(f"{i}. {name} — Lv.{lvl} ({xp_val} XP)")
    embed = discord.Embed(title="🏆 XP 리더보드", description="\n".join(lines), color=0xffc107)
    await ctx.send(embed=embed)

# ---------------------- 공지 (Dyno announce) ----------------------
def _parse_announce_color(raw: Optional[str]) -> Optional[int]:
    if not raw:
        return None
    value = raw.strip().lower()
    if not value:
        return None
    base = 16
    if value.startswith("#"):
        value = value[1:]
    elif value.startswith("0x"):
        value = value[2:]
    elif value.isdigit():
        base = 10
    try:
        number = int(value, base)
    except ValueError:
        return None
    return number if 0 <= number <= 0xFFFFFF else None


def _parse_announce_fields(raw: Optional[str]) -> List[Tuple[str, str, bool]]:
    if not raw:
        return []
    fields: List[Tuple[str, str, bool]] = []
    for chunk in re.split(r"[;\n]+", raw):
        entry = chunk.strip()
        if not entry:
            continue
        parts = [p.strip() for p in entry.split("|", 2)]
        if len(parts) < 2:
            continue
        inline = True
        if len(parts) == 3 and parts[2]:
            inline = parts[2].lower() not in ("false", "0", "no", "n")
        fields.append((parts[0][:256], parts[1][:1024], inline))
        if len(fields) >= 25:
            break
    return fields


async def _normalize_author_name(guild: discord.Guild, raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    match = re.fullmatch(r"\s*<@!?(\d+)>\s*", raw)
    if not match:
        return raw
    user_id = int(match.group(1))
    member = guild.get_member(user_id)
    if member is None:
        try:
            member = await guild.fetch_member(user_id)
        except discord.HTTPException:
            member = None
    if member:
        return member.display_name or member.name
    return raw


@bot.tree.command(name="공지", description="Dyno /announce 스타일의 공지 임베드를 전송합니다")
@app_commands.describe(
    채널="보낼 텍스트 채널 (기본: 현재 채널)",
    제목="임베드 제목",
    설명="임베드 본문",
    내용="공지에 함께 보낼 일반 텍스트",
    색상="임베드 색상 (#RRGGBB, 0x, 또는 10진수)",
    링크="임베드 제목에 연결할 URL",
    이미지="임베드 이미지 URL",
    썸네일="임베드 썸네일 URL",
    필드="세미콜론(;) 또는 줄바꿈으로 구분된 '이름|값|inline' 목록",
    푸터="푸터 텍스트",
    푸터아이콘="푸터 아이콘 URL",
    작성자="작성자(Author) 이름",
    작성자아이콘="작성자 아이콘 URL",
    타임스탬프="현재 시간을 임베드에 포함",
    역할멘션="함께 멘션할 역할",
    모두멘션="@everyone 멘션",
    여기멘션="@here 멘션",
    기본문구="`/공지문구설정`에 저장한 문구를 포함합니다",
    임베드비활성화="체크 시 임베드 없이 텍스트만 전송합니다",
    첨부="임베드 이미지로 사용할 첨부 파일",
    썸네일첨부="임베드 썸네일로 사용할 첨부 파일",
)
async def 공지(
    inter: discord.Interaction,
    채널: Optional[discord.TextChannel] = None,
    제목: Optional[str] = None,
    설명: Optional[str] = None,
    내용: Optional[str] = None,
    색상: Optional[str] = None,
    링크: Optional[str] = None,
    이미지: Optional[str] = None,
    썸네일: Optional[str] = None,
    필드: Optional[str] = None,
    푸터: Optional[str] = None,
    푸터아이콘: Optional[str] = None,
    작성자: Optional[str] = None,
    작성자아이콘: Optional[str] = None,
    타임스탬프: bool = False,
    역할멘션: Optional[discord.Role] = None,
    모두멘션: bool = False,
    여기멘션: bool = False,
    기본문구: bool = False,
    임베드비활성화: bool = False,
    첨부: Optional[discord.Attachment] = None,
    썸네일첨부: Optional[discord.Attachment] = None,
):
    if not inter.guild:
        await inter.response.send_message("서버 내에서만 사용할 수 있습니다.", ephemeral=True)
        return
    perms = inter.user.guild_permissions
    if not perms or not (
        perms.manage_guild or perms.manage_channels or perms.administrator
    ):
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True)
        return
    if (모두멘션 or 여기멘션) and not perms.mention_everyone:
        await inter.response.send_message("@everyone/@here 멘션 권한이 필요합니다.", ephemeral=True)
        return

    target_channel: Optional[discord.abc.MessageableChannel] = 채널
    if target_channel is None:
        if isinstance(inter.channel, (discord.TextChannel, discord.Thread)):
            target_channel = inter.channel
        else:
            await inter.response.send_message("공지 채널을 선택해주세요.", ephemeral=True)
            return
    if not isinstance(target_channel, (discord.TextChannel, discord.Thread)):
        await inter.response.send_message("텍스트 채널이나 스레드만 지원합니다.", ephemeral=True)
        return

    parent_channel = target_channel.parent if isinstance(target_channel, discord.Thread) else target_channel
    bot_member = inter.guild.me
    if bot_member is None:
        try:
            bot_member = await inter.guild.fetch_member(bot.user.id)  # type: ignore[arg-type]
        except Exception:
            bot_member = None
    if bot_member is None:
        await inter.response.send_message("봇 정보를 불러오지 못했습니다.", ephemeral=True)
        return
    bot_perms = parent_channel.permissions_for(bot_member)
    if not bot_perms.send_messages:
        await inter.response.send_message("해당 채널에 메시지를 보낼 권한이 없습니다.", ephemeral=True)
        return
    if not 임베드비활성화 and not bot_perms.embed_links:
        await inter.response.send_message("임베드를 보낼 권한이 없습니다. 임베드를 비활성화하거나 권한을 부여해주세요.", ephemeral=True)
        return

    preset_message = cnm_get(inter.guild_id) if (기본문구 and inter.guild_id) else None
    if inter.guild:
        작성자 = await _normalize_author_name(inter.guild, 작성자)
    if 첨부:
        이미지 = 첨부.url
    if 썸네일첨부:
        썸네일 = 썸네일첨부.url

    color_value = _parse_announce_color(색상)
    if 색상 and color_value is None:
        await inter.response.send_message("색상은 #RRGGBB, 0xRRGGBB 또는 10진수로 입력해주세요.", ephemeral=True)
        return
    fields = _parse_announce_fields(필드)

    embed_description_segments = []
    if 설명:
        embed_description_segments.append(설명)
    if not 임베드비활성화 and preset_message:
        embed_description_segments.append(preset_message)
    embed_description = "\n\n".join(segment for segment in embed_description_segments if segment.strip())

    should_make_embed = not 임베드비활성화 and (
        embed_description
        or 제목
        or 이미지
        or 썸네일
        or fields
        or 푸터
        or 푸터아이콘
        or 작성자
        or 작성자아이콘
        or 링크
        or 타임스탬프
        or color_value is not None
    )

    embed = None
    if should_make_embed:
        embed_kwargs: Dict[str, Any] = {}
        if embed_description:
            embed_kwargs["description"] = embed_description
        if color_value is not None:
            embed_kwargs["color"] = discord.Color(color_value)
        if 링크:
            embed_kwargs["url"] = 링크
        embed = discord.Embed(**embed_kwargs)
        if 제목:
            embed.title = 제목
        author_kwargs: Dict[str, Any] = {}
        if 작성자:
            author_kwargs["name"] = 작성자
        if 작성자아이콘:
            author_kwargs["icon_url"] = 작성자아이콘
        if author_kwargs:
            embed.set_author(**author_kwargs)
        footer_kwargs: Dict[str, Any] = {}
        if 푸터:
            footer_kwargs["text"] = 푸터
        if 푸터아이콘:
            footer_kwargs["icon_url"] = 푸터아이콘
        if footer_kwargs:
            embed.set_footer(**footer_kwargs)
        if 이미지:
            embed.set_image(url=이미지)
        if 썸네일:
            embed.set_thumbnail(url=썸네일)
        for name, value, inline in fields:
            embed.add_field(name=name or "제목 없음", value=value or "\u200b", inline=inline)
        if 타임스탬프:
            embed.timestamp = datetime.now(timezone.utc)

    plain_segments: List[str] = []
    if 모두멘션:
        plain_segments.append("@everyone")
    if 여기멘션:
        plain_segments.append("@here")
    if 역할멘션:
        plain_segments.append(역할멘션.mention)
    if 내용:
        plain_segments.append(내용)
    if (임베드비활성화 or not should_make_embed) and preset_message:
        plain_segments.append(preset_message)
    plain_text = "\n".join(segment for segment in plain_segments if segment).strip() or None

    if not plain_text and embed is None:
        await inter.response.send_message("보낼 내용이 없습니다. 텍스트나 임베드 내용을 입력해주세요.", ephemeral=True)
        return

    allowed_mentions = discord.AllowedMentions(
        users=False,
        roles=bool(역할멘션),
        everyone=bool(모두멘션 or 여기멘션),
    )

    await inter.response.defer(ephemeral=True)
    try:
        await target_channel.send(content=plain_text, embed=embed, allowed_mentions=allowed_mentions)
        log.info(
            "Announcement sent | guild=%s channel=%s user=%s embed=%s",
            inter.guild_id,
            getattr(target_channel, "id", "?"),
            inter.user.id,
            bool(embed),
        )
        await inter.followup.send(f"✅ {target_channel.mention} 채널에 공지를 전송했습니다.", ephemeral=True)
    except discord.Forbidden:
        await inter.followup.send("해당 채널에 메시지를 보낼 권한이 없습니다.", ephemeral=True)
    except discord.HTTPException as e:
        await inter.followup.send(f"공지 전송 중 오류가 발생했습니다: {e}", ephemeral=True)

# ---------------------- 공지 문구 ----------------------
@bot.tree.command(name="공지문구설정", description="공지 기본 문구를 설정합니다")
@app_commands.describe(메시지="저장할 문구")
async def set_notice(inter: discord.Interaction, 메시지: str):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    cnm_set(inter.guild_id, 메시지)
    await inter.response.send_message("✅ 저장되었습니다.", ephemeral=True)

@bot.tree.command(name="공지문구보기", description="저장된 공지 문구를 보여줍니다")
async def get_notice(inter: discord.Interaction):
    msg = cnm_get(inter.guild_id)
    await inter.response.send_message(msg or "저장된 문구가 없습니다.", ephemeral=True)

# ---------------------- 스트림 상태 ----------------------
스트림 = app_commands.Group(name="스트림", description="스트림 상태 관리")
@스트림.command(name="상태설정", description="스트림 상태 값을 설정합니다")
@app_commands.describe(키="키", 값="값")
async def 스트림_설정(inter: discord.Interaction, 키: str, 값: str):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    ss_set(inter.guild_id, 키, 값)
    await inter.response.send_message("✅ 설정되었습니다.", ephemeral=True)

@스트림.command(name="확인", description="스트림 상태 값을 확인합니다")
@app_commands.describe(키="키")
async def 스트림_확인(inter: discord.Interaction, 키: str):
    v = ss_get(inter.guild_id, 키)
    await inter.response.send_message(v or "(없음)", ephemeral=True)

@스트림.command(name="삭제", description="스트림 상태 값을 삭제합니다")
@app_commands.describe(키="키")
async def 스트림_삭제(inter: discord.Interaction, 키: str):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    cnt = ss_remove(inter.guild_id, 키)
    await inter.response.send_message("✅ 삭제되었습니다." if cnt>0 else "대상이 없습니다.", ephemeral=True)

bot.tree.add_command(스트림)

# ============================ 욕설 슬래시 명령 ============================
def _admin_only(inter: discord.Interaction) -> bool:
    perms = inter.user.guild_permissions if inter.guild else None
    return bool(perms and (perms.manage_guild or perms.administrator))

@bot.tree.command(name="욕설상태", description="욕설 필터의 현재 상태를 확인합니다.")
async def profanity_status(inter: discord.Interaction):
    gid = inter.guild_id
    if not gid:
        await inter.response.send_message("서버 내에서만 사용할 수 있습니다.", ephemeral=True); return
    cache = await _ensure_cache(gid)
    embed = discord.Embed(title="🛡️ 욕설 필터 상태", color=0x00c853 if cache["enabled"] else 0x9e9e9e, timestamp=datetime.now(timezone.utc))
    embed.add_field(name="활성화", value="켜짐 ✅" if cache["enabled"] else "꺼짐 ❌", inline=True)
    embed.add_field(name="조치", value=cache["action"].name, inline=True)
    embed.add_field(name="등록 단어 수", value=str(len(cache["words"])), inline=True)
    await inter.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="욕설설정", description="욕설 필터 켜기/끄기 및 조치 설정")
@app_commands.describe(활성화="켜기/끄기", 조치="메시지삭제 또는 경고")
async def profanity_config(inter: discord.Interaction, 활성화: Optional[bool]=None, 조치: Optional[str]=None):
    if not _admin_only(inter):
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    gid = inter.guild_id
    changed = []
    if 활성화 is not None:
        gms_set_enabled(gid, 활성화); changed.append(f"활성화={'켜짐' if 활성화 else '꺼짐'}")
    if 조치 is not None:
        v = (조치 or "").strip().lower()
        if v in ("메시지삭제","삭제","delete"): gms_set_action(gid, ModerationAction.DELETE); changed.append("조치=메시지삭제")
        elif v in ("경고","warn","warning"):     gms_set_action(gid, ModerationAction.WARN);   changed.append("조치=경고")
        else:
            await inter.response.send_message("조치는 '메시지삭제' 또는 '경고' 중에서 선택해 주세요.", ephemeral=True); return
    await _load_guild_cache(gid)
    await inter.response.send_message("변경 없음" if not changed else "✅ " + ", ".join(changed), ephemeral=True)

@bot.tree.command(name="욕설추가", description="금지 단어를 추가합니다.")
@app_commands.describe(단어="추가할 단어(공백 없이 저장)")
async def profanity_add(inter: discord.Interaction, 단어: str):
    if not _admin_only(inter):
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    gid = inter.guild_id
    w = _normalize_word(단어)
    if not w: await inter.response.send_message("단어가 유효하지 않습니다.", ephemeral=True); return
    if bw_exists(gid, w): await inter.response.send_message("이미 등록되어 있습니다.", ephemeral=True); return
    bw_add(gid, w, added_by=inter.user.id)
    await _load_guild_cache(gid)
    await inter.response.send_message(f"✅ 추가됨: `{w}`", ephemeral=True)

@bot.tree.command(name="욕설수정", description="기존 금지 단어를 새 단어로 수정합니다.")
@app_commands.describe(기존단어="기존 단어", 새단어="새 단어")
async def profanity_update(inter: discord.Interaction, 기존단어: str, 새단어: str):
    if not _admin_only(inter):
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    gid = inter.guild_id
    old = _normalize_word(기존단어); new = _normalize_word(새단어)
    if not old or not new:
        await inter.response.send_message("단어가 유효하지 않습니다.", ephemeral=True); return
    if not bw_update(gid, old, new):
        await inter.response.send_message("해당 단어를 찾을 수 없습니다.", ephemeral=True); return
    await _load_guild_cache(gid)
    await inter.response.send_message(f"✏️ 수정됨: `{old}` → `{new}`", ephemeral=True)

@bot.tree.command(name="욕설삭제", description="금지 단어를 삭제합니다.")
@app_commands.describe(단어="삭제할 단어")
async def profanity_delete(inter: discord.Interaction, 단어: str):
    if not _admin_only(inter):
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    gid = inter.guild_id
    w = _normalize_word(단어)
    if not bw_delete(gid, w):
        await inter.response.send_message("해당 단어를 찾을 수 없습니다.", ephemeral=True); return
    await _load_guild_cache(gid)
    await inter.response.send_message(f"🗑️ 삭제됨: `{w}`", ephemeral=True)

@bot.tree.command(name="욕설목록", description="등록된 금지 단어 목록을 확인합니다.")
@app_commands.describe(페이지="기본 1", 페이지크기="기본 20 (최대 100)")
async def profanity_list_cmd(inter: discord.Interaction, 페이지: Optional[int]=1, 페이지크기: Optional[int]=20):
    if not _admin_only(inter):
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    gid = inter.guild_id
    size = max(1, min(페이지크기 or 20, 100)); page = max(1, 페이지 or 1)
    total = bw_count(gid); offset = (page-1)*size
    rows = bw_list(gid, limit=size, offset=offset)
    if not rows:
        await inter.response.send_message("등록된 단어가 없거나 페이지 범위를 벗어났습니다.", ephemeral=True); return
    lines = [f"{offset+i+1}. `{r['word']}`" for i, r in enumerate(rows)]
    embed = discord.Embed(title="🚫 금지 단어 목록", description="\n".join(lines), color=0xff5252)
    embed.set_footer(text=f"페이지 {page} / {(total + size - 1)//size} • 총 {total}개")
    await inter.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="욕설리로드", description="욕설 캐시를 강제로 다시 불러옵니다.")
async def profanity_reload(inter: discord.Interaction):
    if not _admin_only(inter):
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    await _load_guild_cache(inter.guild_id)
    await inter.response.send_message("🔄 캐시를 새로 고쳤습니다.", ephemeral=True)


@bot.tree.command(name="욕설초기화", description="등록된 금지 단어를 모두 삭제합니다.")
async def profanity_reset(inter: discord.Interaction):
    if not _admin_only(inter):
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    gid = inter.guild_id
    cnt = bw_clear(gid)
    await _load_guild_cache(gid)
    msg = f"🧹 금지 단어 {cnt}개를 초기화했습니다." if cnt else "삭제할 금지 단어가 없습니다."
    await inter.response.send_message(msg, ephemeral=True)

# ---------------------- 욕설: 면제 역할 관리 ----------------------
@bot.tree.command(name="욕설면제역할추가", description="욕설 필터를 적용하지 않을 역할을 추가합니다")
async def profanity_bypass_role_add(inter: discord.Interaction, 역할: discord.Role):
    if not _admin_only(inter):
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    ok = pbr_role_add(inter.guild_id, 역할.id)
    try:
        await _load_guild_cache(inter.guild_id)
    except Exception:
        pass
    await inter.response.send_message("✅ 추가되었습니다." if ok else "이미 존재합니다.", ephemeral=True)


@bot.tree.command(name="욕설면제역할삭제", description="욕설 필터 면제 역할을 삭제합니다")
async def profanity_bypass_role_del(inter: discord.Interaction, 역할: discord.Role):
    if not _admin_only(inter):
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    ok = pbr_role_del(inter.guild_id, 역할.id)
    try:
        await _load_guild_cache(inter.guild_id)
    except Exception:
        pass
    await inter.response.send_message("✅ 삭제되었습니다." if ok else "대상이 없습니다.", ephemeral=True)


@bot.tree.command(name="욕설면제역할목록", description="욕설 필터 면제 역할 목록을 확인합니다")
async def profanity_bypass_role_list(inter: discord.Interaction):
    if not _admin_only(inter):
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    ids = pbr_role_ids(inter.guild_id)
    if not ids:
        await inter.response.send_message("(없음)", ephemeral=True); return
    # Format role mentions
    mentions = []
    for rid in ids:
        try:
            r = inter.guild.get_role(int(rid)) if inter.guild else None
            mentions.append(r.mention if r else f"<@&{rid}>")
        except Exception:
            mentions.append(f"<@&{rid}>")
    await inter.response.send_message(", ".join(mentions), ephemeral=True)

# ============================ (NEW) 보안 슬래시 명령 ============================
보안 = app_commands.Group(name="보안", description="보안 설정/화이트리스트/로그 관리")

@보안.command(name="상태", description="보안 설정과 스팸 기준, 화이트리스트 개수를 보여줍니다")
async def sec_status(inter: discord.Interaction):
    s = sec_get(inter.guild_id)
    users, roles, chans = wl_lists(inter.guild_id)
    embed = discord.Embed(title="🧰 보안 상태", color=0x80cbc4, timestamp=datetime.now())
    embed.add_field(name="초대링크 검열", value="켜짐 ✅" if s.block_invites else "꺼짐 ❌", inline=True)
    embed.add_field(name="전체멘션 검열", value="켜짐 ✅" if s.block_everyone else "꺼짐 ❌", inline=True)
    embed.add_field(name="스팸 검열", value="켜짐 ✅" if s.block_spam else "꺼짐 ❌", inline=True)
    embed.add_field(name="스팸 기준", value=f"{s.spam_window_sec}s / {s.spam_threshold}개", inline=True)
    embed.add_field(name="로그 채널", value=f"<#{s.log_channel_id}>" if s.log_channel_id else "(미설정)", inline=True)
    embed.add_field(name="화이트리스트", value=f"유저 {len(users)} / 역할 {len(roles)} / 채널 {len(chans)}", inline=True)
    await inter.response.send_message(embed=embed, ephemeral=True)

@보안.command(name="로그채널설정", description="보안 로그를 보낼 채널을 설정합니다")
@app_commands.describe(채널="텍스트 채널")
async def sec_set_logch(inter: discord.Interaction, 채널: discord.TextChannel):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    sec_update(inter.guild_id, log_channel_id=채널.id)
    await inter.response.send_message(f"✅ 로그 채널: {채널.mention}", ephemeral=True)

@보안.command(name="로그채널해제", description="보안 로그 채널을 해제합니다")
async def sec_unset_logch(inter: discord.Interaction):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    sec_update(inter.guild_id, log_channel_id=None)
    await inter.response.send_message("✅ 로그 채널 해제", ephemeral=True)

@보안.command(name="초대링크검열", description="외부 서버 초대링크 검열 on/off")
async def sec_invite_toggle(inter: discord.Interaction, 켜기: bool):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    sec_update(inter.guild_id, block_invites=켜기)
    await inter.response.send_message(f"✅ 초대링크 검열 {'켜짐' if 켜기 else '꺼짐'}", ephemeral=True)

@보안.command(name="전체멘션검열", description="@everyone/@here 검열 on/off")
async def sec_everyone_toggle(inter: discord.Interaction, 켜기: bool):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    sec_update(inter.guild_id, block_everyone=켜기)
    await inter.response.send_message(f"✅ 전체멘션 검열 {'켜짐' if 켜기 else '꺼짐'}", ephemeral=True)

@보안.command(name="스팸검열", description="스팸(단타/도배) 검열 on/off")
async def sec_spam_toggle(inter: discord.Interaction, 켜기: bool):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    sec_update(inter.guild_id, block_spam=켜기)
    await inter.response.send_message(f"✅ 스팸 검열 {'켜짐' if 켜기 else '꺼짐'}", ephemeral=True)

@보안.command(name="스팸기준", description="스팸 트리거 기준을 설정합니다")
@app_commands.describe(초단위="윈도우 초(기본 7)", 메시지수="허용 메시지 수(기본 5)")
async def sec_spam_threshold(inter: discord.Interaction, 초단위: Optional[int]=None, 메시지수: Optional[int]=None):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    s = sec_get(inter.guild_id)
    win = s.spam_window_sec if 초단위 is None else max(2, min(초단위, 120))
    thr = s.spam_threshold if 메시지수 is None else max(2, min(메시지수, 50))
    sec_update(inter.guild_id, spam_window_sec=win, spam_threshold=thr)
    await inter.response.send_message(f"✅ 스팸 기준: {win}s / {thr}개", ephemeral=True)

@보안.command(name="화이트리스트보기", description="화이트리스트(유저/역할/채널)를 표시합니다")
async def sec_wl_show(inter: discord.Interaction):
    uids, rids, cids = wl_lists(inter.guild_id)
    def _fmt(ids, prefix):
        if not ids: return "(없음)"
        return ", ".join(f"{prefix}{i}>" for i in ids).replace(f"{prefix}","<"+prefix[1:])
    embed = discord.Embed(title="📄 화이트리스트", color=0x90caf9, timestamp=datetime.now())
    embed.add_field(name="유저", value=_fmt(uids, "<@"), inline=False)
    embed.add_field(name="역할", value=_fmt(rids, "<@&"), inline=False)
    embed.add_field(name="채널", value=_fmt(cids, "<#"), inline=False)
    await inter.response.send_message(embed=embed, ephemeral=True)

@보안.command(name="화이트유저추가", description="화이트리스트 유저 추가")
async def sec_wl_user_add(inter: discord.Interaction, 유저: discord.Member):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    ok = wl_user_add(inter.guild_id, 유저.id)
    await inter.response.send_message("✅ 추가되었습니다." if ok else "이미 존재합니다.", ephemeral=True)

@보안.command(name="화이트유저삭제", description="화이트리스트 유저 삭제")
async def sec_wl_user_del(inter: discord.Interaction, 유저: discord.Member):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    ok = wl_user_del(inter.guild_id, 유저.id)
    await inter.response.send_message("✅ 삭제되었습니다." if ok else "대상이 없습니다.", ephemeral=True)

@보안.command(name="화이트역할추가", description="화이트리스트 역할 추가")
async def sec_wl_role_add(inter: discord.Interaction, 역할: discord.Role):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    ok = wl_role_add(inter.guild_id, 역할.id)
    await inter.response.send_message("✅ 추가되었습니다." if ok else "이미 존재합니다.", ephemeral=True)

@보안.command(name="화이트역할삭제", description="화이트리스트 역할 삭제")
async def sec_wl_role_del(inter: discord.Interaction, 역할: discord.Role):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    ok = wl_role_del(inter.guild_id, 역할.id)
    await inter.response.send_message("✅ 삭제되었습니다." if ok else "대상이 없습니다.", ephemeral=True)

@보안.command(name="화이트채널추가", description="화이트리스트 채널 추가")
async def sec_wl_channel_add(inter: discord.Interaction, 채널: discord.TextChannel):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    ok = wl_channel_add(inter.guild_id, 채널.id)
    await inter.response.send_message("✅ 추가되었습니다." if ok else "이미 존재합니다.", ephemeral=True)

@보안.command(name="화이트채널삭제", description="화이트리스트 채널 삭제")
async def sec_wl_channel_del(inter: discord.Interaction, 채널: discord.TextChannel):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    ok = wl_channel_del(inter.guild_id, 채널.id)
    await inter.response.send_message("✅ 삭제되었습니다." if ok else "대상이 없습니다.", ephemeral=True)

bot.tree.add_command(보안)


@보안.command(name="타임아웃보기", description="자동 검열별 타임아웃 시간을 확인합니다 (분 단위)")
async def sec_timeout_show(inter: discord.Interaction):
    t = sto_get(inter.guild_id)
    embed = discord.Embed(title="⏱️ 자동 타임아웃 (분)", color=0xb39ddb, timestamp=datetime.now())
    embed.add_field(name="@everyone/@here", value=f"{t.everyone_min}분", inline=True)
    embed.add_field(name="외부 초대링크", value=f"{t.invite_min}분", inline=True)
    embed.add_field(name="스팸/도배", value=f"{t.spam_min}분", inline=True)
    await inter.response.send_message(embed=embed, ephemeral=True)

@보안.command(name="타임아웃설정", description="자동 검열별 타임아웃(분)을 설정합니다 (1~40320분, 미입력 항목은 유지)")
@app_commands.describe(전체멘션="분 단위 (기본 10)", 초대링크="분 단위 (기본 30)", 스팸="분 단위 (기본 15)")
async def sec_timeout_set(inter: discord.Interaction, 전체멘션: Optional[int]=None, 초대링크: Optional[int]=None, 스팸: Optional[int]=None):
    if not inter.user.guild_permissions.manage_guild:
        await inter.response.send_message("관리자 권한이 필요합니다.", ephemeral=True); return
    def clamp(v): return max(1, min(int(v), 40320))
    updates = {}
    if 전체멘션 is not None: updates["everyone_min"] = clamp(전체멘션)
    if 초대링크 is not None: updates["invite_min"] = clamp(초대링크)
    if 스팸 is not None: updates["spam_min"] = clamp(스팸)
    if not updates:
        await inter.response.send_message("변경할 항목이 없습니다.", ephemeral=True); return
    sto_update(inter.guild_id, **updates)
    t = sto_get(inter.guild_id)
    await inter.response.send_message(f"✅ 설정됨: @everyone/@here={t.everyone_min}분, 초대링크={t.invite_min}분, 스팸={t.spam_min}분", ephemeral=True)



# ============================ 투표 ============================
@bot.tree.command(name="투표생성", description="버튼 투표를 생성합니다 (옵션은 콤마로 구분)")
@app_commands.describe(제목="투표 제목", 옵션들="예: 사과, 배, 포도", 채널="보낼 텍스트 채널 (미지정시 현재 채널)")
async def create_poll(inter: discord.Interaction, 제목: str, 옵션들: str, 채널: Optional[discord.TextChannel] = None):
    await inter.response.defer(ephemeral=True)
    options = [o.strip() for o in 옵션들.split(",") if o.strip()]
    if len(options) < 2:
        await inter.followup.send("❌ 옵션은 최소 2개 이상이어야 합니다. (콤마로 구분)", ephemeral=True); return
    poll_id = uuid.uuid4().hex[:10]
    target_ch = 채널 or inter.channel
    view = PollView(poll_id, options)
    try:
        embed = _format_poll_embed(제목, options, {}, True, inter.user.id, poll_id)
        msg = await target_ch.send(embed=embed, view=view)
        ok_id = poll_create_db(poll_id, inter.guild_id, 제목, json.dumps(options, ensure_ascii=False), msg.id, msg.channel.id, inter.user.id)
        if not ok_id:
            await msg.edit(content="⚠️ DB 저장 중 오류가 발생했습니다. (관리자 확인 필요)", view=view)
            await inter.followup.send("⚠️ 투표 메시지는 보냈지만 DB 저장에 실패했습니다.", ephemeral=True); return
        await inter.followup.send(f"✅ 투표가 생성되었습니다. (ID: `{poll_id}`)", ephemeral=True)
    except Exception as e:
        await inter.followup.send(f"❌ 투표 생성 중 오류: {e}", ephemeral=True)

@bot.tree.command(name="투표종료", description="진행 중인 투표를 종료합니다")
@app_commands.describe(투표아이디="종료할 투표 ID")
async def close_poll(inter: discord.Interaction, 투표아이디: str):
    await inter.response.defer(ephemeral=True)
    data = poll_get_db(투표아이디)
    if not data or not data.is_active:
        await inter.followup.send("❌ 진행 중인 투표를 찾을 수 없습니다.", ephemeral=True); return
    if not (inter.user.guild_permissions.manage_messages or inter.user.id == data.creator_id):
        await inter.followup.send("❌ 이 투표를 종료할 권한이 없습니다.", ephemeral=True); return
    try:
        if not poll_close_db(투표아이디):
            await inter.followup.send("❌ 투표 종료 처리에 실패했습니다.", ephemeral=True); return
        channel = inter.guild.get_channel(int(data.channel_id))
        if isinstance(channel, (discord.TextChannel, discord.Thread, discord.ForumChannel)):
            try:
                msg = await channel.fetch_message(int(data.message_id))
                options = json.loads(data.options) if isinstance(data.options, str) else (data.options or [])
                votes = poll_counts(투표아이디)
                embed = _format_poll_embed(data.title, options, votes, False, data.creator_id, data.poll_id)
                view = PollView(data.poll_id, options, disabled=True)
                await msg.edit(embed=embed, view=view)
            except Exception: pass
        await inter.followup.send(f"✅ 투표가 종료되었습니다. (ID: `{투표아이디}`)", ephemeral=True)
    except Exception as e:
        await inter.followup.send(f"❌ 투표 종료 중 오류: {e}", ephemeral=True)

@bot.tree.command(name="투표결과", description="투표 결과(옵션별 투표자 포함)를 보여줍니다")
@app_commands.describe(투표아이디="투표 ID")
async def poll_result(inter: discord.Interaction, 투표아이디: str):
    data = poll_get_db(투표아이디)
    if not data:
        await inter.response.send_message("❌ 해당 ID의 투표를 찾을 수 없습니다.", ephemeral=True); return
    try:
        options = json.loads(data.options) if isinstance(data.options, str) else (data.options or [])
        counts = poll_counts(투표아이디)
        summary = _format_poll_embed(data.title, options, counts, data.is_active, data.creator_id, data.poll_id)

        grouped = poll_grouped(투표아이디)
        voters_embed = discord.Embed(title="👥 옵션별 투표자", color=0x00c853 if data.is_active else 0x9e9e9e, timestamp=datetime.now())
        for idx, opt in enumerate(options):
            uids = grouped.get(idx, [])
            names = [f"<@{uid}>" for uid in uids]
            voters_embed.add_field(name=f"{idx+1}. {opt} — {len(uids)}표", value=", ".join(names) if names else "없음", inline=False)

        await inter.response.send_message(embeds=[summary, voters_embed], ephemeral=True)
    except Exception as e:
        await inter.response.send_message(f"❌ 결과 조회 중 오류: {e}", ephemeral=True)

# ============================ 실행 ============================
def _get_token() -> str:
    t = os.getenv("DISCORD_TOKEN")
    if not t: raise RuntimeError("DISCORD_TOKEN is required")
    return t

if __name__ == "__main__":
    bot.run(_get_token())
