const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

const JWT_SECRET = process.env.JWT_SECRET || 'kodbank_super_secret_key_2024';

app.use(cors({
  origin: ['http://localhost:3000', 'https://bank1-git-main-r-navyashrees-projects.vercel.app', 'https://bank1-r-navyashrees-projects.vercel.app'],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false }
};

let pool;

async function initDB() {
  pool = mysql.createPool(dbConfig);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS KodUser (
      uid INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(100) NOT NULL UNIQUE,
      email VARCHAR(150) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      balance DECIMAL(15,2) DEFAULT 100000.00,
      phone VARCHAR(20),
      role VARCHAR(50) DEFAULT 'Customer'
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS UserToken (
      tid INT AUTO_INCREMENT PRIMARY KEY,
      token TEXT NOT NULL,
      uid INT NOT NULL,
      expiry DATETIME NOT NULL,
      FOREIGN KEY (uid) REFERENCES KodUser(uid)
    )
  `);

  console.log('✅ Database tables initialized');
}

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, phone } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO KodUser (username, email, password, phone) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, phone]
    );

    res.json({ message: 'Registration successful' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'User already exists' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const [users] = await pool.query('SELECT * FROM KodUser WHERE username = ?', [username]);

    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const token = jwt.sign(
      { role: user.role },
      JWT_SECRET,
      { subject: user.username, expiresIn: '1h' }
    );

    const expiry = new Date(Date.now() + 3600000);
    await pool.query(
      'INSERT INTO UserToken (token, uid, expiry) VALUES (?, ?, ?)',
      [token, user.uid, expiry]
    );

    res.cookie('token', token, { httpOnly: true, maxAge: 3600000, sameSite: 'none', secure: true });
    res.json({ message: 'Login successful', username: user.username });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/getBalance', async (req, res) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const username = decoded.sub;

    const [users] = await pool.query('SELECT balance FROM KodUser WHERE username = ?', [username]);

    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ balance: users[0].balance });
  } catch (error) {
    res.status(401).json({ message: 'Session expired, please login again' });
  }
});

app.post('/api/logout', async (req, res) => {
  const token = req.cookies.token;
  res.clearCookie('token');
  if (token) {
    await pool.query('DELETE FROM UserToken WHERE token = ?', [token]);
  }
  res.json({ message: 'Logged out successfully' });
});

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
  });
});
