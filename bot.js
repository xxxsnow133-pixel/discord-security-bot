// ====== bot.js - Discord Security Bot (Railway-Ready) ======
const { Client, GatewayIntentBits, AuditLogEvent } = require('discord.js');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const bodyParser = require('body-parser');

// ====== KONFIGURATION (aus Environment Variables) ======
const CONFIG = {
  botToken: process.env.BOT_TOKEN,
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL || 'http://localhost:3000/auth/discord/callback',
  sessionSecret: process.env.SESSION_SECRET || 'changeme123',
  port: process.env.PORT || 3000,
  domain: process.env.DOMAIN || 'http://localhost:3000'
};

// Bot Invite URL
const BOT_INVITE = `https://discord.com/api/oauth2/authorize?client_id=${CONFIG.clientId}&permissions=8&scope=bot`;

// Prüfe ob alle wichtigen Variablen gesetzt sind
if (!CONFIG.botToken || !CONFIG.clientId || !CONFIG.clientSecret) {
  console.error('❌ FEHLER: Bitte setze BOT_TOKEN, CLIENT_ID und CLIENT_SECRET als Environment Variables!');
  process.exit(1);
}

// ====== SERVER-EINSTELLUNGEN ======
const guildSettings = new Map();
const defaultSettings = {
  antiNuke: {
    enabled: true,
    channelDeleteLimit: 3,
    channelCreateLimit: 3,
    roleDeleteLimit: 3,
    roleCreateLimit: 3,
    banLimit: 3,
    kickLimit: 3,
    webhookLimit: 2,
    timeWindow: 10000,
    punishment: 'ban',
    timeoutDuration: 600000,
    whitelist: [],
  },
  antiSpam: {
    enabled: true,
    messageLimit: 5,
    timeWindow: 5000,
    punishment: 'timeout',
    timeoutDuration: 300000,
  },
  antiWebhookSpam: {
    enabled: true,
    webhookLimit: 3,
    timeWindow: 10000,
    punishment: 'ban',
  },
  antiLink: {
    enabled: true,
    punishment: 'timeout',
    timeoutDuration: 300000,
    whitelist: [],
  },
  antiInvite: {
    enabled: true,
    punishment: 'kick',
  },
  logging: {
    enabled: true,
    channelId: null,
  }
};

const actionTracking = new Map();
const spamTracking = new Map();

// ====== DISCORD BOT ======
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildModeration,
    GatewayIntentBits.GuildWebhooks,
  ]
});

function getSettings(guildId) {
  if (!guildSettings.has(guildId)) {
    guildSettings.set(guildId, JSON.parse(JSON.stringify(defaultSettings)));
  }
  return guildSettings.get(guildId);
}

async function logAction(guild, message) {
  const settings = getSettings(guild.id);
  if (settings.logging.enabled && settings.logging.channelId) {
    const channel = guild.channels.cache.get(settings.logging.channelId);
    if (channel) {
      await channel.send(`🛡️ **Security Log**: ${message}`).catch(() => {});
    }
  }
}

function trackAction(guildId, userId, actionType) {
  const key = `${guildId}-${userId}-${actionType}`;
  const now = Date.now();
  
  if (!actionTracking.has(key)) {
    actionTracking.set(key, []);
  }
  
  const actions = actionTracking.get(key);
  actions.push(now);
  
  const settings = getSettings(guildId);
  const timeWindow = settings.antiNuke.timeWindow;
  const filtered = actions.filter(time => now - time < timeWindow);
  actionTracking.set(key, filtered);
  
  return filtered.length;
}

async function punishUser(guild, userId, punishment, reason, duration) {
  try {
    const member = await guild.members.fetch(userId).catch(() => null);
    if (!member) return;
    
    const botMember = guild.members.me;
    if (member.roles.highest.position >= botMember.roles.highest.position) {
      await logAction(guild, `⚠️ Kann ${member.user.tag} nicht bestrafen (höhere Rolle)`);
      return;
    }
    
    switch (punishment) {
      case 'ban':
        await member.ban({ reason });
        await logAction(guild, `🔨 ${member.user.tag} wurde gebannt: ${reason}`);
        break;
      case 'kick':
        await member.kick(reason);
        await logAction(guild, `👢 ${member.user.tag} wurde gekickt: ${reason}`);
        break;
      case 'timeout':
        await member.timeout(duration, reason);
        await logAction(guild, `⏰ ${member.user.tag} wurde getimeouted: ${reason}`);
        break;
      case 'removeRoles':
        const roles = member.roles.cache.filter(r => r.id !== guild.id && r.position < botMember.roles.highest.position);
        await member.roles.remove(roles, reason);
        await logAction(guild, `🔻 Rollen von ${member.user.tag} entfernt: ${reason}`);
        break;
    }
  } catch (err) {
    console.error('Fehler bei Bestrafung:', err);
  }
}

// Anti-Nuke Events
client.on('channelDelete', async (channel) => {
  if (!channel.guild) return;
  const settings = getSettings(channel.guild.id);
  if (!settings.antiNuke.enabled) return;
  
  try {
    const audit = await channel.guild.fetchAuditLogs({ type: AuditLogEvent.ChannelDelete, limit: 1 });
    const entry = audit.entries.first();
    if (!entry || entry.createdTimestamp < Date.now() - 5000) return;
    
    const executor = entry.executor;
    if (settings.antiNuke.whitelist.includes(executor.id)) return;
    
    const count = trackAction(channel.guild.id, executor.id, 'channelDelete');
    if (count >= settings.antiNuke.channelDeleteLimit) {
      await punishUser(channel.guild, executor.id, settings.antiNuke.punishment, 
        `Anti-Nuke: ${count} Kanäle gelöscht`, settings.antiNuke.timeoutDuration);
    }
  } catch (err) {
    console.error('Fehler:', err);
  }
});

client.on('channelCreate', async (channel) => {
  if (!channel.guild) return;
  const settings = getSettings(channel.guild.id);
  if (!settings.antiNuke.enabled) return;
  
  try {
    const audit = await channel.guild.fetchAuditLogs({ type: AuditLogEvent.ChannelCreate, limit: 1 });
    const entry = audit.entries.first();
    if (!entry || entry.createdTimestamp < Date.now() - 5000) return;
    
    const executor = entry.executor;
    if (settings.antiNuke.whitelist.includes(executor.id)) return;
    
    const count = trackAction(channel.guild.id, executor.id, 'channelCreate');
    if (count >= settings.antiNuke.channelCreateLimit) {
      await punishUser(channel.guild, executor.id, settings.antiNuke.punishment,
        `Anti-Nuke: ${count} Kanäle erstellt`, settings.antiNuke.timeoutDuration);
    }
  } catch (err) {
    console.error('Fehler:', err);
  }
});

client.on('roleDelete', async (role) => {
  const settings = getSettings(role.guild.id);
  if (!settings.antiNuke.enabled) return;
  
  try {
    const audit = await role.guild.fetchAuditLogs({ type: AuditLogEvent.RoleDelete, limit: 1 });
    const entry = audit.entries.first();
    if (!entry || entry.createdTimestamp < Date.now() - 5000) return;
    
    const executor = entry.executor;
    if (settings.antiNuke.whitelist.includes(executor.id)) return;
    
    const count = trackAction(role.guild.id, executor.id, 'roleDelete');
    if (count >= settings.antiNuke.roleDeleteLimit) {
      await punishUser(role.guild, executor.id, settings.antiNuke.punishment,
        `Anti-Nuke: ${count} Rollen gelöscht`, settings.antiNuke.timeoutDuration);
    }
  } catch (err) {
    console.error('Fehler:', err);
  }
});

client.on('guildBanAdd', async (ban) => {
  const settings = getSettings(ban.guild.id);
  if (!settings.antiNuke.enabled) return;
  
  try {
    const audit = await ban.guild.fetchAuditLogs({ type: AuditLogEvent.MemberBanAdd, limit: 1 });
    const entry = audit.entries.first();
    if (!entry || entry.createdTimestamp < Date.now() - 5000) return;
    
    const executor = entry.executor;
    if (settings.antiNuke.whitelist.includes(executor.id)) return;
    
    const count = trackAction(ban.guild.id, executor.id, 'ban');
    if (count >= settings.antiNuke.banLimit) {
      await punishUser(ban.guild, executor.id, settings.antiNuke.punishment,
        `Anti-Nuke: ${count} Bans`, settings.antiNuke.timeoutDuration);
    }
  } catch (err) {
    console.error('Fehler:', err);
  }
});

client.on('messageCreate', async (message) => {
  if (message.author.bot || !message.guild) return;
  const settings = getSettings(message.guild.id);
  
  // Anti-Spam
  if (settings.antiSpam.enabled) {
    const key = `${message.guild.id}-${message.author.id}`;
    const now = Date.now();
    
    if (!spamTracking.has(key)) {
      spamTracking.set(key, []);
    }
    
    const messages = spamTracking.get(key);
    messages.push(now);
    const filtered = messages.filter(time => now - time < settings.antiSpam.timeWindow);
    spamTracking.set(key, filtered);
    
    if (filtered.length >= settings.antiSpam.messageLimit) {
      await message.delete().catch(() => {});
      await punishUser(message.guild, message.author.id, settings.antiSpam.punishment,
        `Anti-Spam: ${filtered.length} Nachrichten`, settings.antiSpam.timeoutDuration);
      spamTracking.set(key, []);
      return;
    }
  }
  
  // Anti-Link
  if (settings.antiLink.enabled) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const urls = message.content.match(urlRegex);
    
    if (urls) {
      const allowed = urls.every(url => 
        settings.antiLink.whitelist.some(domain => url.includes(domain))
      );
      
      if (!allowed) {
        await message.delete().catch(() => {});
        await punishUser(message.guild, message.author.id, settings.antiLink.punishment,
          'Anti-Link: Unerlaubter Link', settings.antiLink.timeoutDuration);
        return;
      }
    }
  }
  
  // Anti-Invite
  if (settings.antiInvite.enabled) {
    const inviteRegex = /(discord\.gg\/|discord\.com\/invite\/)/i;
    if (inviteRegex.test(message.content)) {
      await message.delete().catch(() => {});
      await punishUser(message.guild, message.author.id, settings.antiInvite.punishment,
        'Anti-Invite: Discord-Einladung', 300000);
    }
  }
});

client.on('ready', () => {
  console.log(`✅ Bot eingeloggt als ${client.user.tag}`);
  console.log(`📊 Auf ${client.guilds.cache.size} Servern aktiv`);
});

// ====== PASSPORT DISCORD OAUTH2 ======
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new DiscordStrategy({
  clientID: CONFIG.clientId,
  clientSecret: CONFIG.clientSecret,
  callbackURL: CONFIG.callbackURL,
  scope: ['identify', 'guilds']
}, (accessToken, refreshToken, profile, done) => {
  profile.accessToken = accessToken;
  return done(null, profile);
}));

// ====== EXPRESS APP ======
const app = express();

app.use(session({
  secret: CONFIG.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 Stunden
  }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Trust proxy (wichtig für Railway/Heroku)
app.set('trust proxy', 1);

function checkAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/');
}

// ====== ROUTES ======
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Bot</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #0a1628 0%, #1a2840 100%);
      color: #fff;
      min-height: 100vh;
    }
    nav {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 20px 60px;
      background: rgba(10, 22, 40, 0.8);
      backdrop-filter: blur(10px);
    }
    .logo {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 20px;
      font-weight: 700;
    }
    .shield-icon {
      width: 40px;
      height: 40px;
      background: linear-gradient(135deg, #5865f2, #7289da);
      clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%);
    }
    .btn {
      padding: 12px 28px;
      border-radius: 8px;
      border: none;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      transition: all 0.3s;
      background: linear-gradient(135deg, #5865f2, #7289da);
      color: #fff;
    }
    .btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(88, 101, 242, 0.4);
    }
    .hero {
      max-width: 1200px;
      margin: 100px auto;
      padding: 0 40px;
      text-align: center;
    }
    h1 {
      font-size: 56px;
      margin-bottom: 20px;
      background: linear-gradient(135deg, #fff, #a0aec0);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    p {
      font-size: 18px;
      color: #a0aec0;
      margin-bottom: 40px;
    }
    .hero-buttons {
      display: flex;
      gap: 20px;
      justify-content: center;
    }
  </style>
</head>
<body>
  <nav>
    <div class="logo">
      <div class="shield-icon"></div>
      SECURITY BOT
    </div>
    <a href="/auth/discord" class="btn">LOGIN</a>
  </nav>
  <div class="hero">
    <h1>🛡️ SECURITY BOT</h1>
    <p>PROTECT YOUR DISCORD SERVER FROM RAIDERS, NUKERS AND ANY TYPE OF DAMAGE.</p>
    <div class="hero-buttons">
      <a href="${BOT_INVITE}" class="btn">ADD BOT</a>
      <a href="/auth/discord" class="btn">DASHBOARD</a>
    </div>
  </div>
</body>
</html>
  `);
});

app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', 
  passport.authenticate('discord', { failureRedirect: '/' }),
  (req, res) => res.redirect('/dashboard')
);

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.get('/dashboard', checkAuth, (req, res) => {
  const userGuilds = req.user.guilds || [];
  const botGuilds = client.guilds.cache.map(g => g.id);
  
  const guildsWithBot = userGuilds.filter(g => 
    botGuilds.includes(g.id) && (parseInt(g.permissions) & 0x8) === 0x8
  );
  
  const guildsWithoutBot = userGuilds.filter(g => 
    !botGuilds.includes(g.id) && (parseInt(g.permissions) & 0x8) === 0x8
  );
  
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: 'Inter', sans-serif;
      background: linear-gradient(135deg, #0a1628 0%, #1a2840 100%);
      color: #fff;
      padding: 20px;
    }
    .container { max-width: 1400px; margin: 0 auto; }
    h1 { font-size: 42px; margin: 40px 0 20px; }
    .guilds-grid { 
      display: grid; 
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); 
      gap: 20px;
      margin: 20px 0;
    }
    .guild-card {
      background: rgba(26, 40, 64, 0.8);
      padding: 25px;
      border-radius: 12px;
      border: 2px solid rgba(255, 255, 255, 0.1);
    }
    .guild-name { font-size: 20px; margin-bottom: 15px; }
    .btn {
      display: block;
      padding: 12px;
      background: linear-gradient(135deg, #5865f2, #7289da);
      color: #fff;
      text-align: center;
      border-radius: 8px;
      text-decoration: none;
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.1);
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Dashboard</h1>
    <h2>Deine Server mit Bot:</h2>
    <div class="guilds-grid">
      ${guildsWithBot.map(g => `
        <div class="guild-card">
          <div class="guild-name">${g.name}</div>
          <a href="/settings/${g.id}" class="btn">Einstellungen</a>
        </div>
      `).join('')}
    </div>
    ${guildsWithoutBot.length > 0 ? `
      <h2>Bot hinzufügen:</h2>
      <div class="guilds-grid">
        ${guildsWithoutBot.map(g => `
          <div class="guild-card">
            <div class="guild-name">${g.name}</div>
            <a href="${BOT_INVITE}&guild_id=${g.id}" class="btn btn-secondary">Bot einladen</a>
          </div>
        `).join('')}
      </div>
    ` : ''}
  </div>
</body>
</html>
  `);
});

app.get('/settings/:guildId', checkAuth, (req, res) => {
  const guildId = req.params.guildId;
  const guild = client.guilds.cache.get(guildId);
  
  if (!guild) {
    return res.send('<h1>Server nicht gefunden!</h1><a href="/dashboard">Zurück</a>');
  }
  
  const settings = getSettings(guildId);
  
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>${guild.name} - Einstellungen</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: 'Inter', sans-serif;
      background: linear-gradient(135deg, #0a1628 0%, #1a2840 100%);
      color: #fff;
      padding: 20px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    .section {
      background: rgba(26, 40, 64, 0.8);
      padding: 30px;
      border-radius: 12px;
      margin: 20px 0;
    }
    h2 { color: #5865f2; margin-bottom: 20px; }
    .setting-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin: 15px 0;
    }
    label { display: block; margin-bottom: 5px; color: #a0aec0; }
    input, select, textarea {
      width: 100%;
      padding: 12px;
      background: rgba(10, 22, 40, 0.6);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      color: #fff;
    }
    button {
      width: 100%;
      padding: 15px;
      background: linear-gradient(135deg, #5865f2, #7289da);
      color: #fff;
      border: none;
      border-radius: 8px;
      font-weight: 600;
      cursor: pointer;
      margin-top: 20px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>${guild.name}</h1>
    <form id="form">
      <div class="section">
        <h2>⚔️ Anti-Nuke</h2>
        <label><input type="checkbox" id="antiNuke_enabled" ${settings.antiNuke.enabled ? 'checked' : ''}> Aktiviert</label>
        <div class="setting-row">
          <div><label>Kanal-Lösch-Limit</label><input type="number" id="antiNuke_channelDeleteLimit" value="${settings.antiNuke.channelDeleteLimit}"></div>
          <div><label>Kanal-Erstell-Limit</label><input type="number" id="antiNuke_channelCreateLimit" value="${settings.antiNuke.channelCreateLimit}"></div>
        </div>
      </div>
      <button type="submit">💾 Speichern</button>
    </form>
  </div>
  <script>
    document.getElementById('form').onsubmit = async (e) => {
      e.preventDefault();
      const data = {
        antiNuke: {
          enabled: document.getElementById('antiNuke_enabled').checked,
          channelDeleteLimit: parseInt(document.getElementById('antiNuke_channelDeleteLimit').value),
          channelCreateLimit: parseInt(document.getElementById('antiNuke_channelCreateLimit').value)
        }
      };
      await fetch('/api/settings/${guildId}', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
      });
      alert('✅ Gespeichert!');
    };
  </script>
</body>
</html>
  `);
});

app.post('/api/settings/:guildId', checkAuth, (req, res) => {
  guildSettings.set(req.params.guildId, req.body);
  res.json({ success: true });
});

// Health Check für Railway
app.get('/health', (req, res) => {
  res.json({ status: 'ok', guilds: client.guilds.cache.size });
});

// ====== START ======
app.listen(CONFIG.port, '0.0.0.0', () => {
  console.log(`🌐 Server läuft auf Port ${CONFIG.port}`);
  console.log(`🔗 Domain: ${CONFIG.domain}`);
});

client.login(CONFIG.botToken).catch(err => {
  console.error('❌ Bot Login fehlgeschlagen:', err);
  process.exit(1);
});
