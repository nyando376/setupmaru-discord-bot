from __future__ import annotations

import discord

WELCOME_COLOR = 0x00FF00


async def send_welcome_message(member: discord.Member) -> None:
    """Send a simple welcome embed to the guild's system channel."""
    channel = getattr(member.guild, "system_channel", None)
    if channel is None:
        return

    embed = discord.Embed(
        title="🎉 새로운 멤버!",
        description=f"{member.mention}님 환영합니다!",
        color=WELCOME_COLOR,
    )
    embed.set_footer(text=member.guild.name)

    try:
        await channel.send(embed=embed)
    except discord.Forbidden:
        # Lack of permissions; ignore quietly.
        pass
    except discord.HTTPException:
        # Discord API error; ignore to keep the bot running.
        pass
