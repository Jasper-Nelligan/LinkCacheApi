require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const { body, validationResult } = require("express-validator");
const authMiddleware = require('./authMiddleware');
const bcrypt = require("bcryptjs");
const { generateToken } = require("./utilities");
const cookieParser = require('cookie-parser');

const corsOptions = {
  origin: 'http://localhost:5173',
  credentials: true,
};

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors(corsOptions));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.get("/authStatus", authMiddleware, (req, res) => {
  console.log("authStatus")
  res.json({ message: "Authenticated" });
});

app.post("/login", [
  body("email").isEmail(),
  body("password").notEmpty()
], async (req, res) => {
  console.log("login")
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  try {
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const isMatch = await bcrypt.compare(password, user.rows[0].password);
    if (!user.rows.length || !isMatch) return res.status(401).json({ message: "Invalid credentials" });

    const token = generateToken(user.rows[0]);

    // Send JWT as an HTTP-only cookie
    res.cookie("token", token, { httpOnly: true, maxAge: 365 * 24 * 60 * 60 * 1000, secure: false });
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
    console.log("register")
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
      res.cookie("token", token, { httpOnly: true, maxAge: 365 * 24 * 60 * 60 * 1000, secure: false }); // TODO change to true for production
      res.status(201).json({ message: "Account created successfully" });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

app.post('/logout', authMiddleware, (req, res) => {
  console.log("logout")
  res.clearCookie("token", {
    httpOnly: true,
    secure: false,
    path: "/",
  });
  res.json({ message: "Logged out successfully" });
});

app.get('/user_data', authMiddleware, async (req, res) => {
  console.log("get user_data")
  const user_id = req.user.id
  console.log(user_id)
  const data = await pool.query(`
    SELECT link_data
    FROM user_data
    INNER JOIN users ON users.id = user_data.id
    WHERE user_data.id = $1;
  `, [user_id]);

  console.log(data.rows)

  res.json(data.rows);
});

app.post('/user_data', authMiddleware, async (req, res) => {
  console.log("post user_data")
  const user_id = req.user.id;
  const linkGroupInfo = req.body.linkGroupInfo;
  console.log("Setting user data for user_id: ", linkGroupInfo);
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

app.listen(3000, () => console.log('Server is running on port 3000'));
