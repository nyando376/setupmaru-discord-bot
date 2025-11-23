import os
import sys

import discord
from discord.ext import commands


def main() -> None:
    token = os.getenv("DISCORD_BOT_TOKEN")
    if not token:
        sys.stderr.write("Set DISCORD_BOT_TOKEN in your environment before running the bot.\n")
        raise SystemExit(1)

    intents = discord.Intents.default()
    bot = commands.Bot(command_prefix="!", intents=intents)

    @bot.event
    async def on_ready() -> None:
        try:
            synced = await bot.tree.sync()
            print(f"Synced {len(synced)} command(s).")
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to sync commands: {exc}")
        print(f"Logged in as {bot.user} (id: {bot.user.id})")

    @bot.tree.command(
        name="hello",
        name_localizations={"ko": "인사"},
        description="Send a simple greeting.",
        description_localizations={"ko": "간단한 인사 메시지를 보냅니다."},
    )
    async def hello(interaction: discord.Interaction) -> None:
        await interaction.response.send_message(f"안녕하세요, {interaction.user.mention}!")

    bot.run('MTQ0MTYyMTU3MjU0ODAzODY1Ng.GXwsWT.FzNfSMMlXgtUIiYRgtqbVLghtY4F73dasGJsY4')


if __name__ == "__main__":
    main()
