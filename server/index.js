require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const path = require("path");
const { pool, migrate } = require("./db");
const { signToken, requireAuth } = require("./auth");

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "../public")));

const COOKIE_OPTS = {
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production",
  maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
};

// ── Auth ──────────────────────────────────────────────────────────────────────

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Заполни все поля" });
  if (username.length < 3) return res.status(400).json({ error: "Имя минимум 3 символа" });
  if (password.length < 6) return res.status(400).json({ error: "Пароль минимум 6 символов" });

  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
      [username.trim(), hash]
    );
    const userId = rows[0].id;
    await pool.query("INSERT INTO user_data (user_id) VALUES ($1) ON CONFLICT DO NOTHING", [userId]);
    res.cookie("token", signToken(userId), COOKIE_OPTS);
    res.json({ ok: true, username: username.trim() });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Имя уже занято" });
    console.error(e);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Заполни все поля" });

  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username.trim()]);
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return res.status(401).json({ error: "Неверное имя или пароль" });

    await pool.query("INSERT INTO user_data (user_id) VALUES ($1) ON CONFLICT DO NOTHING", [user.id]);
    res.cookie("token", signToken(user.id), COOKIE_OPTS);
    res.json({ ok: true, username: user.username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, async (req, res) => {
  const { rows } = await pool.query("SELECT username FROM users WHERE id = $1", [req.userId]);
  if (!rows[0]) return res.status(404).json({ error: "Not found" });
  res.json({ username: rows[0].username });
});

// ── User data sync ────────────────────────────────────────────────────────────

app.get("/api/data", requireAuth, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM user_data WHERE user_id = $1", [req.userId]);
  if (!rows[0]) return res.json({ movies: [], profile: {}, now_state: {}, omdb_ep_cache: {} });
  const r = rows[0];
  res.json({
    movies: r.movies,
    profile: r.profile,
    now_state: r.now_state,
    omdb_ep_cache: r.omdb_ep_cache,
  });
});

app.put("/api/data", requireAuth, async (req, res) => {
  const { movies, profile, now_state, omdb_ep_cache } = req.body;
  await pool.query(
    `INSERT INTO user_data (user_id, movies, profile, now_state, omdb_ep_cache, updated_at)
     VALUES ($1, $2, $3, $4, $5, NOW())
     ON CONFLICT (user_id) DO UPDATE SET
       movies = $2, profile = $3, now_state = $4, omdb_ep_cache = $5, updated_at = NOW()`,
    [
      req.userId,
      JSON.stringify(movies ?? []),
      JSON.stringify(profile ?? {}),
      JSON.stringify(now_state ?? {}),
      JSON.stringify(omdb_ep_cache ?? {}),
    ]
  );
  res.json({ ok: true });
});

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
migrate()
  .then(() => app.listen(PORT, () => console.log(`Netfly server on :${PORT}`)))
  .catch((e) => { console.error("Migration failed", e); process.exit(1); });
