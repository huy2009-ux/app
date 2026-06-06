require('dotenv').config();
const express = require('express');
const session = require('express-session');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'users.json');

// ── Khởi tạo file lưu user ──────────────────────────────────
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]');

function getUsers() {
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function saveUsers(users) {
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

// ── OTP store (in-memory) ────────────────────────────────────
const otpStore = {}; // { email: { otp, expires } }

// ── Nodemailer ───────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

// ── Middleware ───────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }, // 1 ngày
}));

// ── Helper ────────────────────────────────────────────────────
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTP(email, otp) {
  await transporter.sendMail({
    from: `"Auth App" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: '🔐 Mã xác thực OTP của bạn',
    html: `
      <div style="font-family:sans-serif;max-width:400px;margin:auto;padding:30px;border:1px solid #eee;border-radius:12px">
        <h2 style="color:#1a1a2e">Mã xác thực OTP</h2>
        <p>Xin chào! Đây là mã OTP của bạn:</p>
        <div style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#e94560;text-align:center;padding:20px;background:#f5f5f5;border-radius:8px;margin:20px 0">
          ${otp}
        </div>
        <p style="color:#888;font-size:13px">Mã có hiệu lực trong <strong>5 phút</strong>. Không chia sẻ mã này với ai.</p>
      </div>
    `,
  });
}

// ── API Routes ────────────────────────────────────────────────

// Gửi OTP đăng ký
app.post('/api/register/send-otp', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name)
    return res.json({ success: false, message: 'Vui lòng điền đầy đủ thông tin.' });

  const users = getUsers();
  if (users.find(u => u.email === email))
    return res.json({ success: false, message: 'Email này đã được đăng ký.' });

  const otp = generateOTP();
  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000, name, password };

  try {
    await sendOTP(email, otp);
    res.json({ success: true, message: 'OTP đã được gửi đến email của bạn.' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'Không thể gửi email. Kiểm tra lại cấu hình Gmail.' });
  }
});

// Xác thực OTP đăng ký
app.post('/api/register/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore[email];

  if (!record) return res.json({ success: false, message: 'Không tìm thấy OTP. Vui lòng thử lại.' });
  if (Date.now() > record.expires) {
    delete otpStore[email];
    return res.json({ success: false, message: 'OTP đã hết hạn. Vui lòng gửi lại.' });
  }
  if (record.otp !== otp) return res.json({ success: false, message: 'Mã OTP không đúng.' });

  const hashed = await bcrypt.hash(record.password, 10);
  const users = getUsers();
  users.push({ email, name: record.name, password: hashed, createdAt: new Date().toISOString() });
  saveUsers(users);
  delete otpStore[email];

  req.session.user = { email, name: record.name };
  res.json({ success: true, message: 'Đăng ký thành công!' });
});

// Đăng nhập
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const users = getUsers();
  const user = users.find(u => u.email === email);

  if (!user) return res.json({ success: false, message: 'Email không tồn tại.' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.json({ success: false, message: 'Mật khẩu không đúng.' });

  req.session.user = { email: user.email, name: user.name };
  res.json({ success: true, message: 'Đăng nhập thành công!' });
});

// Đăng xuất
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Lấy thông tin user hiện tại
app.get('/api/me', (req, res) => {
  if (req.session.user) res.json({ loggedIn: true, user: req.session.user });
  else res.json({ loggedIn: false });
});

// ── Start ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ Server đang chạy tại: http://localhost:${PORT}\n`);
});
