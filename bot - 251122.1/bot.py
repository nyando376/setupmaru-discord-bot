import logging
import os
from typing import Optional

import discord
from discord.ext import commands


# Basic logging to stdout
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
log = logging.getLogger("welcome-bot")

# Read config from environment
TOKEN = os.getenv("DISCORD_TOKEN")
WELCOME_CHANNEL_ID = os.getenv("WELCOME_CHANNEL_ID")  # Optional: specific channel to post welcomes

# Minimal intents for member join events
intents = discord.Intents.default()
intents.guilds = True
intents.members = True  # Required for on_member_join

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)


@bot.event
async def on_ready():
    log.info("Logged in as %s (%s)", bot.user, bot.user.id if bot.user else "unknown")


def _resolve_welcome_channel(member: discord.Member) -> Optional[discord.TextChannel]:
    """Pick the channel to send the welcome message to."""
    # 1) Use configured channel if provided
    if WELCOME_CHANNEL_ID:
        try:
            channel_id = int(WELCOME_CHANNEL_ID)
            channel = member.guild.get_channel(channel_id)
            if isinstance(channel, discord.TextChannel):
                return channel
            log.warning("WELCOME_CHANNEL_ID %s is not a text channel or not found", WELCOME_CHANNEL_ID)
        except ValueError:
            log.warning("WELCOME_CHANNEL_ID %s is not a valid integer", WELCOME_CHANNEL_ID)

    # 2) Prefer the guild's system channel if allowed
    system_channel = member.guild.system_channel
    if isinstance(system_channel, discord.TextChannel):
        perms = system_channel.permissions_for(member.guild.me)
        if perms.send_messages and perms.view_channel:
            return system_channel

    # 3) Fallback to the first text channel the bot can post in
    for channel in member.guild.text_channels:
        perms = channel.permissions_for(member.guild.me)
        if perms.send_messages and perms.view_channel:
            return channel

    return None


@bot.event
async def on_member_join(member: discord.Member):
    channel = _resolve_welcome_channel(member)
    if not channel:
        log.warning("No available channel to send welcome in guild %s", member.guild.id)
        return

    message = f"환영합니다, {member.mention}! 서버에 오신 것을 환영해요 🎉"
    try:
        await channel.send(message)
        log.info("Sent welcome for %s in guild %s (#%s)", member.id, member.guild.id, channel.id)
    except discord.Forbidden:
        log.warning("Missing permissions to send welcome in channel %s", channel.id)
    except Exception:
        log.exception("Failed to send welcome message")


if __name__ == "__main__":
    if not TOKEN:
        raise RuntimeError("DISCORD_TOKEN is not set")
    bot.run(TOKEN)
