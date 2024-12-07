require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const { body, validationResult } = require("express-validator");
const authMiddleware = require('./authMiddleware');
const bcrypt = require("bcryptjs");
const { generateToken } = require("./utilities");
const cookieParser = require('cookie-parser');

const isProduction = process.env.IS_PRODUCTION === 'true';

const corsOptions = {
  origin: 'https://link-cache.vercel.app/',
  credentials: true,
};

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors(corsOptions));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: isProduction,
  },
});

app.get("/authStatus", authMiddleware, (req, res) => {
  res.json({ message: "Authenticated" });
});

app.post("/login", [
  body("email").isEmail(),
  body("password").notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  try {
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    const isMatch = await bcrypt.compare(password, user.rows[0].password);

    if (!user.rows.length || !isMatch) return res.status(401).json({ message: "Invalid credentials" });

    const token = generateToken(user.rows[0]);

    // Send JWT as an HTTP-only cookie
    res.cookie("token", token, { httpOnly: true, maxAge: 365 * 24 * 60 * 60 * 1000, secure: isProduction });

    res.json({ message: "Logged in successfully" });

  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post('/register', [
  body("email").isEmail().withMessage("Please enter a valid email"),
  body("password")
    .isLength({ min: 8 })
    .withMessage("Password must be at least 6 characters"),
],
  async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;

    try {
      const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
      if (existingUser.rows.length) {
        return res.status(409).json({ message: "Email already in use" });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      const newUser = await pool.query(
        "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
        [email, hashedPassword]
      );

      const token = generateToken(newUser.rows[0]);

      // Send JWT as an HTTP-only cookie
      res.cookie("token", token, { httpOnly: true, maxAge: 365 * 24 * 60 * 60 * 1000, secure: isProduction });
      res.status(201).json({ message: "Account created successfully" });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

app.post('/logout', authMiddleware, (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: isProduction,
    path: "/",
  });
  res.json({ message: "Logged out successfully" });
});

app.get('/user_data', authMiddleware, async (req, res) => {
  const user_id = req.user.id
  const data = await pool.query(`
    SELECT link_data
    FROM user_data
    INNER JOIN users ON users.id = user_data.id
    WHERE user_data.id = $1;
  `, [user_id]);

  res.json(data.rows);
});

app.post('/user_data', authMiddleware, async (req, res) => {
  const user_id = req.user.id;
  const linkGroupInfo = req.body.linkGroupInfo;
  try {
    await pool.query(`
      INSERT INTO user_data (id, link_data)
      VALUES ($1, $2)
      ON CONFLICT (id)
      DO UPDATE SET link_data = EXCLUDED.link_data;
    `, [user_id, linkGroupInfo]);
    res.json({ message: "Data inserted/updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/user_email', authMiddleware, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await pool.query("SELECT email FROM users WHERE id = $1", [userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ email: result.rows[0].email });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(3000, () => console.log('Server is running on port 3000'));
