require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const path = require("path");
const { Resend } = require("resend");
const { pool, migrate } = require("./db");
const { signToken, requireAuth } = require("./auth");

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "../public")));

const resend = new Resend(process.env.RESEND_API_KEY);
const FROM_EMAIL = process.env.FROM_EMAIL || "noreply@yourdomain.com";

const COOKIE_OPTS = {
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production",
  maxAge: 30 * 24 * 60 * 60 * 1000,
};

app.get("/health", (req, res) => res.json({ ok: true }));

// ── Email verification ────────────────────────────────────────────────────────

app.post("/api/send-code", async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password)
    return res.status(400).json({ error: "Заполни все поля" });
  if (username.length < 3)
    return res.status(400).json({ error: "Имя минимум 3 символа" });
  if (password.length < 6)
    return res.status(400).json({ error: "Пароль минимум 6 символов" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "Некорректный email" });

  try {
    // Check duplicates
    const { rows } = await pool.query(
      "SELECT id FROM users WHERE email=$1 OR username=$2",
      [email.toLowerCase(), username.trim()]
    );
    if (rows.length) return res.status(409).json({ error: "Email или имя уже заняты" });

    // Generate 6-digit code
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min

    // Invalidate old codes for this email
    await pool.query("UPDATE verification_codes SET used=TRUE WHERE email=$1", [email.toLowerCase()]);

    await pool.query(
      "INSERT INTO verification_codes (email, code, expires_at) VALUES ($1, $2, $3)",
      [email.toLowerCase(), code, expiresAt]
    );

    await resend.emails.send({
      from: FROM_EMAIL,
      to: email,
      subject: "Netfly — код подтверждения",
      html: `<p>Твой код подтверждения: <b style="font-size:24px">${code}</b></p><p>Действителен 10 минут.</p>`,
    });

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка отправки письма" });
  }
});

app.post("/api/verify-code", async (req, res) => {
  const { email, username, password, code } = req.body;
  if (!email || !username || !password || !code)
    return res.status(400).json({ error: "Заполни все поля" });

  try {
    const { rows } = await pool.query(
      `SELECT * FROM verification_codes
       WHERE email=$1 AND code=$2 AND used=FALSE AND expires_at > NOW()
       ORDER BY id DESC LIMIT 1`,
      [email.toLowerCase(), code.trim()]
    );

    if (!rows.length)
      return res.status(400).json({ error: "Неверный или истёкший код" });

    // Mark code as used
    await pool.query("UPDATE verification_codes SET used=TRUE WHERE id=$1", [rows[0].id]);

    const hash = await bcrypt.hash(password, 10);
    const insert = await pool.query(
      "INSERT INTO users (email, username, password_hash, verified) VALUES ($1,$2,$3,TRUE) RETURNING id",
      [email.toLowerCase(), username.trim(), hash]
    );
    const userId = insert.rows[0].id;
    await pool.query("INSERT INTO user_data (user_id) VALUES ($1)", [userId]);

    res.cookie("token", signToken(userId), COOKIE_OPTS);
    res.json({ ok: true, username: username.trim() });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Email или имя уже заняты" });
    console.error(e);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// ── Auth ──────────────────────────────────────────────────────────────────────

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Заполни все поля" });

  try {
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE email=$1 OR username=$1",
      [email.trim().toLowerCase()]
    );
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return res.status(401).json({ error: "Неверный email/имя или пароль" });

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
  const { rows } = await pool.query("SELECT username FROM users WHERE id=$1", [req.userId]);
  if (!rows[0]) return res.status(404).json({ error: "Not found" });
  res.json({ username: rows[0].username });
});

// ── User data sync ────────────────────────────────────────────────────────────

app.get("/api/data", requireAuth, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM user_data WHERE user_id=$1", [req.userId]);
  if (!rows[0]) return res.json({ movies: [], profile: {}, now_state: {}, omdb_ep_cache: {} });
  const r = rows[0];
  res.json({ movies: r.movies, profile: r.profile, now_state: r.now_state, omdb_ep_cache: r.omdb_ep_cache });
});

app.put("/api/data", requireAuth, async (req, res) => {
  const { movies, profile, now_state, omdb_ep_cache } = req.body;
  await pool.query(
    `INSERT INTO user_data (user_id, movies, profile, now_state, omdb_ep_cache, updated_at)
     VALUES ($1,$2,$3,$4,$5,NOW())
     ON CONFLICT (user_id) DO UPDATE SET
       movies=$2, profile=$3, now_state=$4, omdb_ep_cache=$5, updated_at=NOW()`,
    [req.userId, JSON.stringify(movies??[]), JSON.stringify(profile??{}),
     JSON.stringify(now_state??{}), JSON.stringify(omdb_ep_cache??{})]
  );
  res.json({ ok: true });
});

// ── Kinopoisk proxy ───────────────────────────────────────────────────────────

const KP_KEY = process.env.KP_API_KEY;
const KP_HEADERS = { "X-API-KEY": KP_KEY, "Content-Type": "application/json" };

app.get("/api/kp/search", async (req, res) => {
  const { keyword, page = 1 } = req.query;
  if (!keyword) return res.status(400).json({ error: "keyword required" });
  try {
    const r = await fetch(
      `https://kinopoiskapiunofficial.tech/api/v2.1/films/search-by-keyword?keyword=${encodeURIComponent(keyword)}&page=${page}`,
      { headers: KP_HEADERS }
    );
    res.json(await r.json());
  } catch { res.status(500).json({ error: "KP error" }); }
});

app.get("/api/kp/seasons/:id", async (req, res) => {
  try {
    const r = await fetch(`https://kinopoiskapiunofficial.tech/api/v2.2/films/${req.params.id}/seasons`, { headers: KP_HEADERS });
    res.json(await r.json());
  } catch { res.status(500).json({ error: "KP error" }); }
});

app.get("/api/kp/seasons/:id", async (req, res) => {
  try {
    const r = await fetch(`https://kinopoiskapiunofficial.tech/api/v2.2/films/${req.params.id}/seasons`, { headers: KP_HEADERS });
    res.json(await r.json());
  } catch { res.status(500).json({ error: "KP error" }); }
});

app.get("/api/kp/film/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const [film, staff] = await Promise.all([
      fetch(`https://kinopoiskapiunofficial.tech/api/v2.2/films/${id}`, { headers: KP_HEADERS }).then(r => r.json()),
      fetch(`https://kinopoiskapiunofficial.tech/api/v1/staff?filmId=${id}`, { headers: KP_HEADERS }).then(r => r.json()),
    ]);
    const directors = Array.isArray(staff) ? staff.filter(s => s.professionKey === "DIRECTOR").map(s => s.nameRu || s.nameEn).filter(Boolean) : [];
    const actors = Array.isArray(staff) ? staff.filter(s => s.professionKey === "ACTOR").slice(0, 5).map(s => s.nameRu || s.nameEn).filter(Boolean) : [];
    res.json({ ...film, directors, actors });
  } catch { res.status(500).json({ error: "KP error" }); }
});

// ── Telegram integration ──────────────────────────────────────────────────────

const TG_SECRET = process.env.TG_SECRET;

// Generate link code (called from site, requires auth)
app.post("/api/tg/gen-code", requireAuth, async (req, res) => {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  await pool.query("UPDATE link_codes SET used=TRUE WHERE user_id=$1", [req.userId]);
  await pool.query(
    "INSERT INTO link_codes (user_id, code, expires_at) VALUES ($1,$2,$3)",
    [req.userId, code, expiresAt]
  );
  res.json({ code });
});

// Verify link code + bind telegram_id (called from bot)
app.post("/api/tg/verify-link", async (req, res) => {
  if (req.headers["x-tg-secret"] !== TG_SECRET)
    return res.status(403).json({ error: "Forbidden" });
  const { code, telegram_id } = req.body;
  if (!code || !telegram_id) return res.status(400).json({ error: "Bad request" });

  const { rows } = await pool.query(
    `SELECT * FROM link_codes WHERE code=$1 AND used=FALSE AND expires_at > NOW() LIMIT 1`,
    [code]
  );
  if (!rows.length) return res.status(400).json({ error: "Неверный или истёкший код" });

  await pool.query("UPDATE link_codes SET used=TRUE WHERE id=$1", [rows[0].id]);
  await pool.query(
    `INSERT INTO telegram_links (telegram_id, user_id) VALUES ($1,$2)
     ON CONFLICT (telegram_id) DO UPDATE SET user_id=$2, linked_at=NOW()`,
    [telegram_id, rows[0].user_id]
  );
  const user = await pool.query("SELECT username FROM users WHERE id=$1", [rows[0].user_id]);
  res.json({ ok: true, username: user.rows[0].username });
});

// Auto-login via Telegram Mini App initData
app.post("/api/tg/webapp-login", async (req, res) => {
  const { initData } = req.body;
  if (!initData) return res.status(400).json({ error: "No initData" });

  const crypto = require("crypto");
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  params.delete("hash");
  params.delete("signature");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  const secretKey = crypto.createHmac("sha256", "WebAppData").update(process.env.TG_TOKEN).digest();
  const expectedHash = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");

  console.log("hash from client:", hash);
  console.log("expected hash:", expectedHash);
  console.log("raw initData:", initData.substring(0, 200));

  if (expectedHash !== hash) return res.status(403).json({ error: "Invalid initData" });

  const user = JSON.parse(params.get("user") || "{}");
  const telegramId = user.id;
  if (!telegramId) return res.status(400).json({ error: "No user in initData" });

  const link = await pool.query("SELECT user_id FROM telegram_links WHERE telegram_id=$1", [telegramId]);
  if (!link.rows.length) return res.status(404).json({ error: "Account not linked" });

  const userId = link.rows[0].user_id;
  res.cookie("token", signToken(userId), COOKIE_OPTS);
  const u = await pool.query("SELECT username FROM users WHERE id=$1", [userId]);
  res.json({ ok: true, username: u.rows[0].username });
});

// Get profile data by telegram_id (called from bot)
app.get("/api/tg/profile", async (req, res) => {
  if (req.headers["x-tg-secret"] !== TG_SECRET)
    return res.status(403).json({ error: "Forbidden" });
  const { telegram_id } = req.query;
  if (!telegram_id) return res.status(400).json({ error: "Bad request" });

  const link = await pool.query("SELECT user_id FROM telegram_links WHERE telegram_id=$1", [telegram_id]);
  if (!link.rows.length) return res.status(404).json({ error: "Аккаунт не привязан" });

  const userId = link.rows[0].user_id;
  const [userRes, dataRes] = await Promise.all([
    pool.query("SELECT username FROM users WHERE id=$1", [userId]),
    pool.query("SELECT movies, profile FROM user_data WHERE user_id=$1", [userId]),
  ]);

  const username = userRes.rows[0]?.username || "";
  const movies = dataRes.rows[0]?.movies || [];
  const profile = dataRes.rows[0]?.profile || {};

  const watched = movies.filter(m => (m.status || "watched") === "watched");
  const scores = watched.map(m => {
    const vals = Object.values(m.scores || {}).filter(v => typeof v === "number");
    return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
  }).filter(s => s !== null);
  const avgScore = scores.length ? (scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(1) : null;

  const best = watched
    .map(m => {
      const vals = Object.values(m.scores || {}).filter(v => typeof v === "number");
      const final = vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : 0;
      return { name: m.name, final };
    })
    .sort((a, b) => b.final - a.final)[0] || null;

  res.json({
    username,
    watched_count: watched.length,
    avg_score: avgScore,
    best_movie: best?.name || null,
    fav_director: profile.favDirectorName || null,
    fav_actor: profile.favActorName || null,
  });
});

// ── Password reset ────────────────────────────────────────────────────────────

app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Введи email" });

  try {
    const { rows } = await pool.query("SELECT id FROM users WHERE email=$1", [email.toLowerCase()]);
    // Always respond OK to avoid email enumeration
    if (!rows.length) return res.json({ ok: true });

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query("UPDATE verification_codes SET used=TRUE WHERE email=$1", [email.toLowerCase()]);
    await pool.query(
      "INSERT INTO verification_codes (email, code, expires_at) VALUES ($1, $2, $3)",
      [email.toLowerCase(), code, expiresAt]
    );

    await resend.emails.send({
      from: FROM_EMAIL,
      to: email,
      subject: "Netfly — сброс пароля",
      html: `<p>Код для сброса пароля: <b style="font-size:24px">${code}</b></p><p>Действителен 10 минут.</p>`,
    });

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка отправки письма" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  const { email, code, password } = req.body;
  if (!email || !code || !password) return res.status(400).json({ error: "Заполни все поля" });
  if (password.length < 6) return res.status(400).json({ error: "Пароль минимум 6 символов" });

  try {
    const { rows } = await pool.query(
      `SELECT * FROM verification_codes
       WHERE email=$1 AND code=$2 AND used=FALSE AND expires_at > NOW()
       ORDER BY id DESC LIMIT 1`,
      [email.toLowerCase(), code.trim()]
    );
    if (!rows.length) return res.status(400).json({ error: "Неверный или истёкший код" });

    await pool.query("UPDATE verification_codes SET used=TRUE WHERE id=$1", [rows[0].id]);

    const hash = await bcrypt.hash(password, 10);
    await pool.query("UPDATE users SET password_hash=$1 WHERE email=$2", [hash, email.toLowerCase()]);

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
migrate()
  .then(() => app.listen(PORT, () => console.log(`Netfly server on :${PORT}`)))
  .catch((e) => { console.error("Migration failed", e); process.exit(1); });
