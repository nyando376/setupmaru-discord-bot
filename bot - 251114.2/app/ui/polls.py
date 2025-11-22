from __future__ import annotations

from datetime import datetime
from typing import List, Dict

import discord

from app.services.polls import poll_vote

# 투표 UI 구성요소를 한곳에서 정의해 슬래시 명령과 버튼 이벤트를 한글 메시지로 안내합니다.


class PollView(discord.ui.View):
    def __init__(self, poll_id: str, options: List[str], disabled: bool = False):
        super().__init__(timeout=None)
        self.poll_id = poll_id or ""
        self.options = options or []
        for idx, label in enumerate(self.options):
            btn = discord.ui.Button(
                style=discord.ButtonStyle.secondary,
                label=(label or f"옵션 {idx+1}")[:80],
                custom_id=f"poll:{self.poll_id}:{idx}",
                disabled=disabled,
            )

            async def _cb(
                interaction: discord.Interaction, index=idx, pid=self.poll_id
            ):
                ok = poll_vote(pid, interaction.user.id, index)
                if ok:
                    await interaction.response.send_message(
                        "✅ 투표가 반영되었습니다.", ephemeral=True
                    )
                else:
                    await interaction.response.send_message(
                        "❌ 투표를 진행할 수 없습니다.", ephemeral=True
                    )

            btn.callback = _cb
            self.add_item(btn)


def format_poll_embed(
    title: str,
    options: List[str],
    votes: Dict[int, int],
    active: bool,
    creator_id: int,
    poll_id: str,
):
    total = sum(votes.values()) if votes else 0
    lines = []
    for i, opt in enumerate(options):
        cnt = votes.get(i, 0)
        bar_len = 15
        pct = int(round((cnt / total) * bar_len)) if total else 0
        bar = "█" * pct + "─" * (bar_len - pct)
        lines.append(f"{i+1}. {opt} — {cnt}표  [{bar}]")
    desc = "\n".join(lines) if lines else "옵션이 없습니다."
    embed = discord.Embed(
        title=f"🗳️ 투표: {title}",
        description=desc,
        color=0x00C853 if active else 0x9E9E9E,
        timestamp=datetime.now(),
    )
    embed.add_field(name="상태", value=("진행중" if active else "종료"), inline=True)
    embed.add_field(name="총 투표수", value=str(total), inline=True)
    embed.add_field(name="투표 ID", value=poll_id, inline=True)
    embed.set_footer(text=f"생성자: {creator_id}")
    return embed
