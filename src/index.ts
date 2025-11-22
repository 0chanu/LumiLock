import 'dotenv/config';
import { Client, Events, GatewayIntentBits, Partials } from 'discord.js';
import messageCreate from './events/messageCreate';

const token = process.env.DISCORD_TOKEN;

if (!token) {
  console.error('DISCORD_TOKEN is not set. Check your environment variables.');
  process.exit(1);
}

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ],
  partials: [Partials.Channel]
});

client.once(Events.ClientReady, (readyClient) => {
  console.log(`✅ Logged in as ${readyClient.user.tag}`);
});

client.on(Events.MessageCreate, async (message) => {
  try {
    await messageCreate.execute(message);
  } catch (error) {
    console.error('[messageCreate] handler error:', error);
  }
});

client.login(token).catch((error) => {
  console.error('Failed to login to Discord:', error);
  process.exit(1);
});
