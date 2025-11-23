require('dotenv').config();
const { REST, Routes, SlashCommandBuilder } = require('discord.js');

if (!process.env.DISCORD_TOKEN || !process.env.DISCORD_CLIENT_ID || !process.env.DISCORD_GUILD_ID) {
  console.error('DISCORD_TOKEN, DISCORD_CLIENT_ID, DISCORD_GUILD_ID 환경 변수가 필요합니다. .env 파일을 확인하세요.');
  process.exit(1);
}

const commands = [
  new SlashCommandBuilder()
    .setName('hello')
    .setDescription('봇이 인사해요')
    .addStringOption(option =>
      option
        .setName('name')
        .setDescription('같이 인사할 이름을 입력해주세요')
    )
    .setDMPermission(false)
    .toJSON(),
];

const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);

(async () => {
  try {
    console.log('디스코드에 /hello 명령어 등록 중...');
    await rest.put(
      Routes.applicationGuildCommands(process.env.DISCORD_CLIENT_ID, process.env.DISCORD_GUILD_ID),
      { body: commands },
    );
    console.log('등록 완료!');
  } catch (error) {
    console.error('명령어 등록 실패:', error);
    process.exit(1);
  }
})();
