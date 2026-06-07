require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'users.json');
const FRIENDS_FILE = path.join(__dirname, 'friends.json');
const MESSAGES_FILE = path.join(__dirname, 'messages.json');

if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]');
if (!fs.existsSync(FRIENDS_FILE)) fs.writeFileSync(FRIENDS_FILE, '{}');
if (!fs.existsSync(MESSAGES_FILE)) fs.writeFileSync(MESSAGES_FILE, '{}');

function getUsers() { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
function saveUsers(u) { fs.writeFileSync(DB_FILE, JSON.stringify(u, null, 2)); }
function getFriends() { return JSON.parse(fs.readFileSync(FRIENDS_FILE, 'utf8')); }
function saveFriends(f) { fs.writeFileSync(FRIENDS_FILE, JSON.stringify(f, null, 2)); }
function getMessages() { return JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8')); }
function saveMessages(m) { fs.writeFileSync(MESSAGES_FILE, JSON.stringify(m, null, 2)); }

const otpStore = {};
const onlineUsers = {}; // email -> socketId

async function sendOTP(email, otp) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'onboarding@resend.dev',
      to: email,
      subject: '🔐 Mã xác thực OTP',
      html: `<div style="font-family:sans-serif;max-width:400px;margin:auto;padding:30px;border:1px solid #eee;border-radius:12px"><h2>Mã OTP</h2><div style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#e94560;text-align:center;padding:20px;background:#f5f5f5;border-radius:8px;margin:20px 0">${otp}</div><p style="color:#888;font-size:13px">Hiệu lực 5 phút.</p></div>`,
    }),
  });
  if (!res.ok) throw new Error('Resend error');
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 86400000 }
});
app.use(sessionMiddleware);

function generateOTP() { return Math.floor(100000 + Math.random() * 900000).toString(); }

// ── AUTH ──
app.post('/api/register/send-otp', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) return res.json({ success: false, message: 'Điền đầy đủ thông tin.' });
  const users = getUsers();
  if (users.find(u => u.email === email)) return res.json({ success: false, message: 'Email đã đăng ký.' });
  const otp = generateOTP();
  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000, name, password };
  try {
    await sendOTP(email, otp);
    res.json({ success: true, message: 'OTP đã gửi!' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'Không thể gửi email.' });
  }
});

app.post('/api/register/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore[email];
  if (!record) return res.json({ success: false, message: 'Không tìm thấy OTP.' });
  if (Date.now() > record.expires) { delete otpStore[email]; return res.json({ success: false, message: 'OTP hết hạn.' }); }
  if (record.otp !== otp) return res.json({ success: false, message: 'Mã OTP sai.' });
  const hashed = await bcrypt.hash(record.password, 10);
  const users = getUsers();
  users.push({ email, name: record.name, password: hashed, createdAt: new Date().toISOString() });
  saveUsers(users);
  delete otpStore[email];
  req.session.user = { email, name: record.name };
  res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const users = getUsers();
  const user = users.find(u => u.email === email);
  if (!user) return res.json({ success: false, message: 'Email không tồn tại.' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ success: false, message: 'Mật khẩu sai.' });
  req.session.user = { email: user.email, name: user.name };
  res.json({ success: true });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/me', (req, res) => {
  if (req.session.user) res.json({ loggedIn: true, user: req.session.user });
  else res.json({ loggedIn: false });
});

// ── USERS ──
app.get('/api/users', (req, res) => {
  if (!req.session.user) return res.json({ success: false });
  const users = getUsers().map(u => ({ email: u.email, name: u.name, online: !!onlineUsers[u.email] }));
  res.json({ success: true, users });
});

// ── FRIENDS ──
app.get('/api/friends', (req, res) => {
  if (!req.session.user) return res.json({ success: false });
  const friends = getFriends();
  const myEmail = req.session.user.email;
  const data = friends[myEmail] || { friends: [], sent: [], received: [] };
  const users = getUsers();
  const enrich = (email) => {
    const u = users.find(x => x.email === email);
    return { email, name: u ? u.name : email, online: !!onlineUsers[email] };
  };
  res.json({
    success: true,
    friends: data.friends.map(enrich),
    sent: data.sent.map(enrich),
    received: data.received.map(enrich),
  });
});

app.post('/api/friends/request', (req, res) => {
  if (!req.session.user) return res.json({ success: false });
  const from = req.session.user.email;
  const { to } = req.body;
  if (from === to) return res.json({ success: false, message: 'Không thể tự kết bạn.' });
  const friends = getFriends();
  if (!friends[from]) friends[from] = { friends: [], sent: [], received: [] };
  if (!friends[to]) friends[to] = { friends: [], sent: [], received: [] };
  if (friends[from].friends.includes(to)) return res.json({ success: false, message: 'Đã là bạn bè.' });
  if (friends[from].sent.includes(to)) return res.json({ success: false, message: 'Đã gửi lời mời.' });
  friends[from].sent.push(to);
  friends[to].received.push(from);
  saveFriends(friends);
  // Thông báo real-time
  const fromUser = getUsers().find(u => u.email === from);
  if (onlineUsers[to]) {
    io.to(onlineUsers[to]).emit('friend_request', { from, name: fromUser ? fromUser.name : from });
  }
  res.json({ success: true });
});

app.post('/api/friends/accept', (req, res) => {
  if (!req.session.user) return res.json({ success: false });
  const me = req.session.user.email;
  const { from } = req.body;
  const friends = getFriends();
  if (!friends[me] || !friends[from]) return res.json({ success: false });
  friends[me].received = friends[me].received.filter(e => e !== from);
  friends[from].sent = friends[from].sent.filter(e => e !== me);
  friends[me].friends.push(from);
  friends[from].friends.push(me);
  saveFriends(friends);
  const meUser = getUsers().find(u => u.email === me);
  if (onlineUsers[from]) {
    io.to(onlineUsers[from]).emit('friend_accepted', { from: me, name: meUser ? meUser.name : me });
  }
  res.json({ success: true });
});

app.post('/api/friends/decline', (req, res) => {
  if (!req.session.user) return res.json({ success: false });
  const me = req.session.user.email;
  const { from } = req.body;
  const friends = getFriends();
  if (!friends[me]) return res.json({ success: false });
  friends[me].received = friends[me].received.filter(e => e !== from);
  if (friends[from]) friends[from].sent = friends[from].sent.filter(e => e !== me);
  saveFriends(friends);
  res.json({ success: true });
});

// ── MESSAGES ──
app.get('/api/messages/:friendEmail', (req, res) => {
  if (!req.session.user) return res.json({ success: false });
  const me = req.session.user.email;
  const friend = req.params.friendEmail;
  const key = [me, friend].sort().join('|');
  const messages = getMessages();
  res.json({ success: true, messages: messages[key] || [] });
});

// ── SOCKET.IO ──
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

io.on('connection', (socket) => {
  const user = socket.request.session?.user;
  if (!user) return socket.disconnect();

  onlineUsers[user.email] = socket.id;
  io.emit('user_online', { email: user.email });

  socket.on('send_message', ({ to, text }) => {
    const from = user.email;
    const key = [from, to].sort().join('|');
    const messages = getMessages();
    if (!messages[key]) messages[key] = [];
    const msg = { from, text, time: new Date().toISOString() };
    messages[key].push(msg);
    saveMessages(messages);
    if (onlineUsers[to]) io.to(onlineUsers[to]).emit('new_message', { from, text, time: msg.time });
    socket.emit('new_message', { from, text, time: msg.time });
  });

  socket.on('disconnect', () => {
    delete onlineUsers[user.email];
    io.emit('user_offline', { email: user.email });
  });
});

server.listen(PORT, () => console.log(`\n✅ Server chạy tại: http://localhost:${PORT}\n`));
