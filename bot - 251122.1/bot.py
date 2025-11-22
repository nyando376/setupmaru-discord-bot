"""A minimal Discord bot that posts a welcome message when someone joins."""

import logging
import os

import discord
from discord.ext import commands

from app import send_welcome_message


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

intents = discord.Intents.default()
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    logging.info("Bot ready as %s (%s)", bot.user, getattr(bot.user, "id", "?"))


@bot.event
async def on_member_join(member: discord.Member):
    await send_welcome_message(member)


def main() -> None:
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        raise RuntimeError("DISCORD_TOKEN environment variable is required")
    bot.run(token)


if __name__ == "__main__":
    main()
