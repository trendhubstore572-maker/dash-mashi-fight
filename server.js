/* =========================================================================
   داش ماشی فایت — GAME SERVER
   Node.js + Express + Socket.IO + SQLite (better-sqlite3)
   Run:  npm install && node server.js
   ========================================================================= */

/* ---------------- 1. REQUIRE STATEMENTS ---------------- */
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const { Server } = require('socket.io');

/* ---------------- 2. DATABASE SETUP ---------------- */
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'game.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  coins INTEGER DEFAULT 200,
  wins INTEGER DEFAULT 0,
  losses INTEGER DEFAULT 0,
  rank_points INTEGER DEFAULT 100,
  character_id TEXT DEFAULT 'mashi',
  suit_id TEXT DEFAULT 'suit_black',
  hat_id TEXT DEFAULT 'hat_black',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS purchases (
  user_id INTEGER NOT NULL,
  item_id TEXT NOT NULL,
  type TEXT NOT NULL,
  PRIMARY KEY (user_id, item_id)
);`);

/* ---------------- 3. GAME DATA (characters & shop catalog) ---------------- */
const CHARACTERS = [
  { id: 'mashi',    name: 'داش ماشی', desc: 'متعادل و مرگبار', hp: 100, power: 12, speed: 5, defense: 5, skin: '#e8b88a' },
  { id: 'tehrani',  name: 'تهرونی',   desc: 'سریع و چابک',    hp: 95,  power: 10, speed: 7, defense: 4, skin: '#d9a06b' },
  { id: 'esfahani', name: 'اصفهانی',  desc: 'سنگین و مستحکم', hp: 120, power: 9,  speed: 4, defense: 8, skin: '#f0c8a0' },
  { id: 'shirazi',  name: 'شیرازی',   desc: 'مشت آهنین',      hp: 105, power: 14, speed: 5, defense: 3, skin: '#c98f5a' },
];

const SUITS = [
  { id: 'suit_black', name: 'کت مشکی کلاسیک', price: 0,    color: '#26262e' },
  { id: 'suit_brown', name: 'کت قهوه‌ای',     price: 300,  color: '#6b4226' },
  { id: 'suit_navy',  name: 'کت سرمه‌ای',     price: 500,  color: '#23314f' },
  { id: 'suit_wine',  name: 'کت شرابی',       price: 800,  color: '#7a2438' },
  { id: 'suit_white', name: 'کت سفید خاص',    price: 1500, color: '#e8e4d8' },
];

const HATS = [
  { id: 'hat_black', name: 'کلاه مشکی',   price: 0,   color: '#1b1b1b' },
  { id: 'hat_brown', name: 'کلاه قهوه‌ای', price: 200, color: '#4a3220' },
  { id: 'hat_grey',  name: 'کلاه طوسی',   price: 400, color: '#555a63' },
  { id: 'hat_red',   name: 'کلاه قرمز',   price: 900, color: '#8a1f2d' },
];

const ITEMS = [
  ...SUITS.map(s => ({ ...s, type: 'suit' })),
  ...HATS.map(h => ({ ...h, type: 'hat' })),
];

/* ---------------- 4. HELPER FUNCTIONS ---------------- */
const hashPassword = (pw, salt) =>
  crypto.scryptSync(String(pw), salt, 64).toString('hex');

const getUser = id => db.prepare('SELECT * FROM users WHERE id = ?').get(id);
const getUserByName = name => db.prepare('SELECT * FROM users WHERE username = ?').get(name);

const tokens = new Map(); // token -> userId

function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    coins: u.coins,
    wins: u.wins,
    losses: u.losses,
    rank_points: u.rank_points,
    character_id: u.character_id,
    suit_id: u.suit_id,
    hat_id: u.hat_id,
  };
}

function authMiddleware(req, res, next) {
  const uid = tokens.get(req.headers['x-token']);
  if (!uid) return res.status(401).json({ error: 'ابتدا وارد شوید' });
  const user = getUser(uid);
  if (!user) return res.status(401).json({ error: 'نشست نامعتبر است' });
  req.user = user;
  next();
}

const itemOf = (list, id) => list.find(i => i.id === id) || list[0];

function fighterPayload(user) {
  const c = CHARACTERS.find(x => x.id === user.character_id) || CHARACTERS[0];
  return {
    username: user.username,
    stats: c,
    suitColor: itemOf(SUITS, user.suit_id).color,
    hatColor: itemOf(HATS, user.hat_id).color,
  };
}

/* ---------------- 5. EXPRESS APP (with CORS for AppMint client) ---------------- */
const app = express();
app.use(express.json());

// CORS — required because the client HTML is hosted on AppMint, not this server
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-token');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

/* ---------------- 6. API ENDPOINTS ---------------- */

// Register
app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || username.length < 3 || password.length < 4)
    return res.status(400).json({ error: 'نام کاربری حداقل ۳ و رمز حداقل ۴ کاراکتر' });
  if (getUserByName(username))
    return res.status(400).json({ error: 'این نام کاربری قبلاً گرفته شده' });

  const salt = crypto.randomBytes(16).toString('hex');
  const info = db.prepare('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)')
    .run(username, hashPassword(password, salt), salt);
  const user = getUser(info.lastInsertRowid);
  const token = crypto.randomBytes(24).toString('hex');
  tokens.set(token, user.id);
  res.json({ token, user: publicUser(user) });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = getUserByName(username || '');
  if (!user || hashPassword(password || '', user.salt) !== user.password_hash)
    return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });
  const token = crypto.randomBytes(24).toString('hex');
  tokens.set(token, user.id);
  res.json({ token, user: publicUser(user) });
});

// Current profile
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// Shop & character catalog
app.get('/api/catalog', (req, res) => {
  res.json({ characters: CHARACTERS, suits: SUITS, hats: HATS });
});

// Leaderboard
app.get('/api/leaderboard', (req, res) => {
  const rows = db.prepare(
    'SELECT username, wins, losses, rank_points FROM users ORDER BY rank_points DESC LIMIT 50'
  ).all();
  res.json({ leaderboard: rows });
});

// Select character
app.post('/api/character/select', authMiddleware, (req, res) => {
  const c = CHARACTERS.find(c => c.id === (req.body || {}).character_id);
  if (!c) return res.status(400).json({ error: 'شخصیت نامعتبر' });
  db.prepare('UPDATE users SET character_id = ? WHERE id = ?').run(c.id, req.user.id);
  res.json({ user: publicUser(getUser(req.user.id)) });
});

// Buy shop item
app.post('/api/shop/buy', authMiddleware, (req, res) => {
  const item = ITEMS.find(i => i.id === (req.body || {}).item_id);
  if (!item) return res.status(400).json({ error: 'آیتم نامعتبر' });
  const owned = db.prepare('SELECT 1 FROM purchases WHERE user_id = ? AND item_id = ?')
    .get(req.user.id, item.id);
  if (owned) return res.status(400).json({ error: 'قبلاً خریداری شده' });
  if (req.user.coins < item.price) return res.status(400).json({ error: 'سکه کافی نیست!' });
  db.prepare('UPDATE users SET coins = coins - ? WHERE id = ?').run(item.price, req.user.id);
  db.prepare('INSERT INTO purchases (user_id, item_id, type) VALUES (?, ?, ?)')
    .run(req.user.id, item.id, item.type);
  res.json({ user: publicUser(getUser(req.user.id)), message: 'خرید موفق! 🎉' });
});

// Equip shop item
app.post('/api/shop/equip', authMiddleware, (req, res) => {
  const item = ITEMS.find(i => i.id === (req.body || {}).item_id);
  if (!item) return res.status(400).json({ error: 'آیتم نامعتبر' });
  const owned = db.prepare('SELECT 1 FROM purchases WHERE user_id = ? AND item_id = ?')
    .get(req.user.id, item.id);
  if (!owned) return res.status(400).json({ error: 'ابتدا باید بخرید' });
  db.prepare(`UPDATE users SET ${item.type}_id = ? WHERE id = ?`).run(item.id, req.user.id);
  res.json({ user: publicUser(getUser(req.user.id)) });
});

// AI-mode rewards
app.post('/api/ai_reward', authMiddleware, (req, res) => {
  const result = (req.body || {}).result;
  const reward = result === 'win' ? 40 : 10;
  db.prepare('UPDATE users SET coins = coins + ? WHERE id = ?').run(reward, req.user.id);
  if (result === 'win')
    db.prepare('UPDATE users SET wins = wins + 1, rank_points = rank_points + 5 WHERE id = ?').run(req.user.id);
  else
    db.prepare('UPDATE users SET losses = losses + 1 WHERE id = ?').run(req.user.id);
  res.json({ user: publicUser(getUser(req.user.id)) });
});

/* ---------------- 7. SOCKET.IO MULTIPLAYER ---------------- */
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' },  // allow connections from AppMint-hosted client
});

const queue = [];        // socket ids waiting for random matchmaking
const rooms = new Map(); // roomCode -> { code, sockets[], host, done }
const matches = new Map(); // socketId -> { code, opp, host, userId }

const genCode = () => Math.random().toString(36).substring(2, 6).toUpperCase();

const oppOf = sid => {
  const m = matches.get(sid);
  return m ? m.opp : null;
};

function startMatch(a, b) {
  const code = genCode();
  rooms.set(code, { code, sockets: [a.id, b.id], host: a.id, done: false });
  matches.set(a.id, { code, opp: b.id, host: true,  userId: a.data.user.id });
  matches.set(b.id, { code, opp: a.id, host: false, userId: b.data.user.id });
  a.join(code);
  b.join(code);
  a.emit('matchFound', { playerNum: 1, host: true,  opponent: fighterPayload(b.data.user) });
  b.emit('matchFound', { playerNum: 2, host: false, opponent: fighterPayload(a.data.user) });
}

io.on('connection', (socket) => {
  // Authenticate socket via token
  const userId = tokens.get(socket.handshake.auth && socket.handshake.auth.token);
  const user = userId && getUser(userId);
  if (!user) return socket.disconnect(true);
  socket.data.user = user;
  console.log(`👤 connected: ${user.username} (${socket.id})`);

  /* ----- Matchmaking ----- */
  socket.on('findMatch', () => {
    if (matches.has(socket.id)) return;
    if (!queue.includes(socket.id)) queue.push(socket.id);
    socket.emit('searching');
    if (queue.length >= 2) {
      const [idA, idB] = queue.splice(0, 2);
      const a = io.sockets.sockets.get(idA);
      const b = io.sockets.sockets.get(idB);
      if (a && b) startMatch(a, b);
      else if (a) queue.push(a.id); // one of them vanished; put the other back
    }
  });

  socket.on('cancelMatch', () => {
    const i = queue.indexOf(socket.id);
    if (i >= 0) queue.splice(i, 1);
  });

  /* ----- Rooms (create/join with code) ----- */
  socket.on('createRoom', () => {
    if (matches.has(socket.id)) return;
    const code = genCode();
    rooms.set(code, { code, sockets: [socket.id], host: socket.id, done: false });
    matches.set(socket.id, { code, opp: null, host: true, userId: user.id });
    socket.join(code);
    socket.emit('roomCreated', { code });
  });

  socket.on('joinRoom', ({ code } = {}) => {
    const room = rooms.get(String(code || '').toUpperCase());
    if (!room) return socket.emit('errorMsg', 'اتاق پیدا نشد!');
    if (room.sockets.length >= 2) return socket.emit('errorMsg', 'اتاق پر است!');
    const hostSocket = io.sockets.sockets.get(room.host);
    if (!hostSocket) return socket.emit('errorMsg', 'میزبان اتاق offline است');
    room.sockets.push(socket.id);
    matches.set(socket.id, { code: room.code, opp: room.host, host: false, userId: user.id });
    matches.get(room.host).opp = socket.id;
    socket.join(room.code);
    socket.emit('roomJoined',    { playerNum: 2, host: false, opponent: fighterPayload(hostSocket.data.user) });
    hostSocket.emit('opponentJoined', { playerNum: 1, host: true,  opponent: fighterPayload(user) });
  });

  /* ----- In-game real-time relay ----- */
  socket.on('state', s => {
    const o = oppOf(socket.id);
    if (o) io.to(o).emit('state', s);
  });
  socket.on('attack', a => {
    const o = oppOf(socket.id);
    if (o) io.to(o).emit('attack', a);
  });
  socket.on('time', t => {
    const o = oppOf(socket.id);
    if (o) io.to(o).emit('time', t);
  });
  socket.on('roundEnd', r => {
    const m = matches.get(socket.id);
    if (m && m.host) socket.to(m.code).emit('roundEnd', r);
  });
  socket.on('roundStart', r => {
    const m = matches.get(socket.id);
    if (m && m.host) socket.to(m.code).emit('roundStart', r);
  });
  socket.on('chat', ({ msg } = {}) => {
    const o = oppOf(socket.id);
    if (o && typeof msg === 'string' && msg.trim())
      io.to(o).emit('chat', { username: user.username, msg: msg.trim().slice(0, 120) });
  });

  /* ----- Match end (host reports; server applies rewards) ----- */
  socket.on('matchEnd', ({ winnerUserId } = {}) => {
    const m = matches.get(socket.id);
    if (!m || !m.host || !m.opp) return;
    const room = rooms.get(m.code);
    if (!room || room.done) return;
    room.done = true;

    const oppUserId = (matches.get(m.opp) || {}).userId;
    let winnerId;
    if (winnerUserId === 'me') winnerId = m.userId;
    else if (winnerUserId === 'opp') winnerId = oppUserId;
    else winnerId = winnerUserId;
    if (winnerId !== m.userId && winnerId !== oppUserId) return;

    const loserId = winnerId === m.userId ? oppUserId : m.userId;
    db.prepare('UPDATE users SET wins = wins + 1, coins = coins + 150, rank_points = rank_points + 25 WHERE id = ?').run(winnerId);
    db.prepare('UPDATE users SET losses = losses + 1, coins = coins + 50 WHERE id = ?').run(loserId);

    for (const sid of room.sockets) {
      const mm = matches.get(sid);
      if (!mm) continue;
      const fresh = getUser(mm.userId);
      io.to(sid).emit('matchResult', {
        winnerUserId: winnerId,
        youWon: mm.userId === winnerId,
        user: publicUser(fresh),
      });
    }

    setTimeout(() => {
      for (const sid of room.sockets) {
        const mm = matches.get(sid);
        if (mm) {
          const s = io.sockets.sockets.get(sid);
          if (s) s.leave(m.code);
          matches.delete(sid);
        }
      }
      rooms.delete(m.code);
    }, 1000);
  });

  /* ----- Leave / disconnect ----- */
  socket.on('leaveGame', () => cleanup(socket));

  socket.on('disconnect', () => {
    console.log(`👋 disconnected: ${user.username} (${socket.id})`);
    const i = queue.indexOf(socket.id);
    if (i >= 0) queue.splice(i, 1);
    const o = oppOf(socket.id);
    if (o) io.to(o).emit('opponentLeft');
    cleanup(socket);
  });
});

function cleanup(socket) {
  const m = matches.get(socket.id);
  if (!m) return;
  const room = rooms.get(m.code);
  if (room) {
    socket.leave(m.code);
    if (room.sockets.length <= 1) rooms.delete(m.code);
    else room.sockets = room.sockets.filter(s => s !== socket.id);
  }
  matches.delete(socket.id);
}

/* ---------------- 8. START SERVER ---------------- */
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log('🥊 داش ماشی فایت سرور اجرا شد');
  console.log(`📡 WebSocket + API: ws://YOUR_SERVER_IP:${PORT}`);
});
