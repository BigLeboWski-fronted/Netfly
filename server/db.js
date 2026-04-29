const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS verification_codes (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used BOOLEAN NOT NULL DEFAULT FALSE
    );

    CREATE TABLE IF NOT EXISTS user_data (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      movies JSONB NOT NULL DEFAULT '[]',
      profile JSONB NOT NULL DEFAULT '{}',
      now_state JSONB NOT NULL DEFAULT '{}',
      omdb_ep_cache JSONB NOT NULL DEFAULT '{}',
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

  `);

  // Account change cooldown columns
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS username_changed_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_changed_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;
  `);

  // Indexes
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_verification_codes_email ON verification_codes(email);
  `);

  // Safe migrations for existing tables
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT FALSE;
  `);
  // Cleanup legacy Telegram tables and indexes
  await pool.query(`
    DROP INDEX IF EXISTS idx_link_codes_code;
    DROP INDEX IF EXISTS idx_telegram_links_telegram_id;
    DROP TABLE IF EXISTS link_codes;
    DROP TABLE IF EXISTS telegram_links;
  `);
  // Fill email from username for old rows, then make unique+not null
  await pool.query(`UPDATE users SET email = username WHERE email IS NULL;`);
  await pool.query(`
    ALTER TABLE users ALTER COLUMN email SET NOT NULL;
  `).catch(() => {});
}

module.exports = { pool, migrate };
