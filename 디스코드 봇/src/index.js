require('dotenv').config();
const { Client, GatewayIntentBits, Events } = require('discord.js');

if (!process.env.DISCORD_TOKEN) {
  console.error('DISCORD_TOKEN 환경 변수가 필요합니다. .env 파일을 확인하세요.');
  process.exit(1);
}

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

client.once(Events.ClientReady, readyClient => {
  console.log(`Ready! Logged in as ${readyClient.user.tag}`);
});

client.on(Events.InteractionCreate, async interaction => {
  if (!interaction.isChatInputCommand()) return;
  if (interaction.commandName !== 'hello') return;

  const requestedName =
    interaction.options.getString('name') ||
    interaction.member?.displayName ||
    interaction.user.globalName ||
    interaction.user.username;

  const greeting = `안녕하세요, ${requestedName}!`;

  try {
    await interaction.reply({ content: greeting });
  } catch (error) {
    console.error('인사 응답 실패:', error);
  }
});

client.login(process.env.DISCORD_TOKEN);
