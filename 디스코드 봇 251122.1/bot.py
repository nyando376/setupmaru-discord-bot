import logging
import os

import discord
from discord.ext import commands

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

intents = discord.Intents.default()
intents.members = True  # Required to receive member join events

bot = commands.Bot(command_prefix='!', intents=intents, description='Welcome bot')


@bot.event
async def on_ready():
    logging.info('Logged in as %s (ID: %s)', bot.user, bot.user.id)


@bot.event
async def on_member_join(member: discord.Member):
    channel = member.guild.system_channel
    welcome_message = f"{member.mention}님, 서버에 오신 것을 환영해요!"

    if channel is not None:
        await channel.send(welcome_message)
    else:
        try:
            await member.send(welcome_message)
        except discord.HTTPException:
            logging.info('Could not send welcome DM to %s', member)


def main():
    token = os.getenv('DISCORD_BOT_TOKEN')
    if not token:
        raise SystemExit('환경 변수 DISCORD_BOT_TOKEN을 설정해주세요.')

    bot.run(token)


if __name__ == '__main__':
    main()
