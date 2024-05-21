const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./config');
const { authenticateToken } = require('./middleware');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;

// Giriş rotası için hız sınırlama
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: 5, // Her 15 dakikada 5 istekle sınırlayın
  message: 'Çok fazla giriş denemesi yapıldı, lütfen daha sonra tekrar deneyin'
});

// Kayıt Ol
router.post('/register', [
  body('username').isString().isLength({ min: 3 }).trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }).trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password, email } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', [username, hashedPassword, email]);
    res.status(201).json({ message: 'Kullanıcı başarıyla kaydedildi!' });
  } catch (error) {
    res.status(500).json(error);
  }
});

// router.post('/register', async (req, res) => {
//   const { username, password, email } = req.body;
//   try {
//     const hashedPassword = await bcrypt.hash(password, 10);
//     const [rows] = await pool.query('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', [username, hashedPassword, email]);
//     res.status(201).json({ message: 'User registered successfully!' });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// Giriş Yap
router.post('/login', loginLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }).trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(400).json({ message: 'Geçersiz bilgiler' });

    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).json({ message: 'Geçersiz bilgiler' });

    const token = jwt.sign({ userId: user.id, username: user.username, email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Kullanıcı Güncelle
router.put('/update', authenticateToken, [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email } = req.body;
  const userId = req.user.userId;
  try {
    await pool.query('UPDATE users SET email = ? WHERE id = ?', [email, userId]);
    res.json({ message: 'Kullanıcı başarıyla güncellendi!' });
  } catch (error) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

module.exports = router;
