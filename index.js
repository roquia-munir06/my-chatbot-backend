import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import pkg from "pg";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import { OAuth2Client } from "google-auth-library";

dotenv.config();
const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 5000;
const isProd = process.env.NODE_ENV === "production";

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});

// Google OAuth client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Middleware
app.use(cors({
  origin: ["http://localhost:3000", "https://chatbot-e91e.vercel.app/"],
  credentials: true
}));
app.use(bodyParser.json());
app.use(cookieParser());

// JWT helper functions
const createAccessToken = (user) =>
  jwt.sign({ id: user.id, email: user.email, name: user.name  }, process.env.JWT_SECRET, { expiresIn: "15m" });

const createRefreshToken = (user) =>
  jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });

const verifyAccessToken = (req, res, next) => {
  const token = req.cookies.accessToken;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

// ---------------- Email/Password Auth ---------------- //

// Signup
app.post("/signup", async (req, res) => {
  const { name, email, password, confirm } = req.body;
  if (password !== confirm) return res.status(400).json({ message: "Passwords do not match" });

  try {
    const existingUser = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (existingUser.rows.length > 0) return res.status(400).json({ message: "Email already registered" });

    const password_hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash) VALUES ($1,$2,$3) RETURNING *",
      [name, email, password_hash]
    );

    const user = result.rows[0];
    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user);

    res.cookie("accessToken", accessToken, { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax", maxAge: 15*60*1000 });
    res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax", maxAge: 7*24*60*60*1000 });

    res.status(200).json({ message: "User registered successfully", user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Signin
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;
  try {
    const userResult = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (userResult.rows.length === 0) return res.status(400).json({ message: "Invalid email or password" });

    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(400).json({ message: "Invalid email or password" });

    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user);

    res.cookie("accessToken", accessToken, { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax", maxAge: 15*60*1000 });
    res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax", maxAge: 7*24*60*60*1000 });

    res.status(200).json({ message: "Login successful", user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- Google Sign-In ---------------- //

app.post("/api/auth/google", async (req, res) => {
  const { token } = req.body;

  try {
    // 1️⃣ Verify Google token
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    // 2️⃣ Check if user exists in DB
    let userResult = await pool.query("SELECT * FROM users WHERE google_id=$1", [googleId]);
    let user;
    if (userResult.rows.length === 0) {
      // Check if email exists from normal signup
      let emailResult = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
      if (emailResult.rows.length > 0) {
        // Link Google ID to existing account
        user = emailResult.rows[0];
        await pool.query("UPDATE users SET google_id=$1 WHERE id=$2", [googleId, user.id]);
      } else {
        // 3️⃣ Create new user
        const insertResult = await pool.query(
          "INSERT INTO users (name, email, google_id) VALUES ($1, $2, $3) RETURNING *",
          [name, email, googleId]
        );
        user = insertResult.rows[0];
      }
    } else {
      user = userResult.rows[0];
    }

    // 4️⃣ Generate session/JWT
    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user);

    res.cookie("accessToken", accessToken, { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax", maxAge: 15*60*1000 });
    res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax", maxAge: 7*24*60*60*1000 });

    res.status(200).json({ message: "Google login successful", user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: "Google authentication failed" });
  }
});

// ---------------- Refresh token / Logout / Protected ---------------- //

app.post("/refresh_token", async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ message: "No refresh token provided" });

  try {
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    const userResult = await pool.query("SELECT * FROM users WHERE id=$1", [decoded.id]);
    const user = userResult.rows[0];

    const newAccessToken = createAccessToken(user);
    res.cookie("accessToken", newAccessToken, { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax", maxAge: 15*60*1000 });
    res.status(200).json({ message: "Access token refreshed" });
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired refresh token" });
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("accessToken", { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax" });
  res.clearCookie("refreshToken", { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax" });
  res.status(200).json({ message: "Logged out successfully" });
});

app.get("/dashboard", verifyAccessToken, (req, res) => {
  res.status(200).json({ message: `Welcome ${req.user.email}`, user: req.user });
});

app.get("/", (req, res) => res.send("Backend is working!"));

app.get("/verify", verifyAccessToken, async (req, res) => {
  try {
    // Optional: fetch full user info from DB
    const userResult = await pool.query("SELECT id, name, email FROM users WHERE id=$1", [req.user.id]);
    const user = userResult.rows[0];
    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));










// import express from "express";
// import cors from "cors";
// import bodyParser from "body-parser";
// import bcrypt from "bcrypt";
// import pkg from "pg";
// import jwt from "jsonwebtoken";
// import cookieParser from "cookie-parser";
// import dotenv from "dotenv";

// dotenv.config();
// const { Pool } = pkg;

// const app = express();
// const PORT = process.env.PORT || 5000;
// const isProd = process.env.NODE_ENV === "production";

// // Middleware
// app.use(cors({
//   origin: "http://localhost:3000", // frontend domain
//   credentials: true
// }));
// app.use(bodyParser.json());
// app.use(cookieParser());

// // PostgreSQL connection
// const pool = new Pool({
//   user: process.env.DB_USER,
//   host: process.env.DB_HOST,
//   database: process.env.DB_NAME,
//   password: process.env.DB_PASSWORD,
//   port: process.env.DB_PORT
// });

// // Helper functions
// const createAccessToken = (user) =>
//   jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "15m" });

// const createRefreshToken = (user) =>
//   jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });

// const verifyAccessToken = (req, res, next) => {
//   const token = req.cookies.accessToken;
//   if (!token) return res.status(401).json({ message: "Unauthorized" });

//   try {
//     req.user = jwt.verify(token, process.env.JWT_SECRET);
//     next();
//   } catch {
//     res.status(401).json({ message: "Invalid or expired token" });
//   }
// };

// // Signup
// app.post("/signup", async (req, res) => {
//   const { name, email, password, confirm } = req.body;
//   if (password !== confirm) return res.status(400).json({ message: "Passwords do not match" });

//   try {
//     const existingUser = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
//     if (existingUser.rows.length > 0) return res.status(400).json({ message: "Email already registered" });

//     const password_hash = await bcrypt.hash(password, 12);
//     const result = await pool.query(
//       "INSERT INTO users (name, email, password_hash) VALUES ($1,$2,$3) RETURNING *",
//       [name, email, password_hash]
//     );

//     const user = result.rows[0];
//     const accessToken = createAccessToken(user);
//     const refreshToken = createRefreshToken(user);

//     // Set cookies with correct flags for dev/prod
//     res.cookie("accessToken", accessToken, {
//       httpOnly: true,
//       secure: isProd,
//       sameSite: isProd ? "Strict" : "Lax",
//       maxAge: 15*60*1000
//     });
//     res.cookie("refreshToken", refreshToken, {
//       httpOnly: true,
//       secure: isProd,
//       sameSite: isProd ? "Strict" : "Lax",
//       maxAge: 7*24*60*60*1000
//     });

//     res.status(200).json({ message: "User registered successfully", user: { id: user.id, name: user.name, email: user.email } });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: "Server error" });
//   }
// });

// // Signin
// app.post("/signin", async (req, res) => {
//   const { email, password } = req.body;
//   try {
//     const userResult = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
//     if (userResult.rows.length === 0) return res.status(400).json({ message: "Invalid email or password" });

//     const user = userResult.rows[0];
//     const isMatch = await bcrypt.compare(password, user.password_hash);
//     if (!isMatch) return res.status(400).json({ message: "Invalid email or password" });

//     const accessToken = createAccessToken(user);
//     const refreshToken = createRefreshToken(user);

//     res.cookie("accessToken", accessToken, { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax", maxAge: 15*60*1000 });
//     res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax", maxAge: 7*24*60*60*1000 });

//     res.status(200).json({ message: "Login successful", user: { id: user.id, name: user.name, email: user.email } });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: "Server error" });
//   }
// });

// // Refresh access token
// app.post("/refresh_token", async (req, res) => {
//   const token = req.cookies.refreshToken;
//   if (!token) return res.status(401).json({ message: "No refresh token provided" });

//   try {
//     const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
//     const userResult = await pool.query("SELECT * FROM users WHERE id=$1", [decoded.id]);
//     const user = userResult.rows[0];

//     const newAccessToken = createAccessToken(user);
//     res.cookie("accessToken", newAccessToken, { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax", maxAge: 15*60*1000 });
//     res.status(200).json({ message: "Access token refreshed" });
//   } catch (err) {
//     return res.status(401).json({ message: "Invalid or expired refresh token" });
//   }
// });

// // Logout
// app.post("/logout", (req, res) => {
//   res.clearCookie("accessToken", { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax" });
//   res.clearCookie("refreshToken", { httpOnly: true, secure: isProd, sameSite: isProd ? "Strict" : "Lax" });
//   res.status(200).json({ message: "Logged out successfully" });
// });

// // Protected route
// app.get("/dashboard", verifyAccessToken, (req, res) => {
//   res.status(200).json({ message: `Welcome ${req.user.email}`, user: req.user });
// });

// // Test route
// app.get("/", (req, res) => res.send("Backend is working!"));

// // Start server
// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
