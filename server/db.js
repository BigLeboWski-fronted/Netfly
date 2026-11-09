const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 3,
  connectionTimeoutMillis: 15000,
  idleTimeoutMillis: 10000,
  // Verify the database certificate in production to prevent MITM connections.
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: true } : false,
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
      used BOOLEAN NOT NULL DEFAULT FALSE,
      attempts INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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

  // Brute-force protection for existing installations.
  await pool.query(`
    ALTER TABLE verification_codes ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE verification_codes ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_verification_codes_created_at ON verification_codes(created_at);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS rate_limit_buckets (
      bucket_key TEXT PRIMARY KEY,
      count INTEGER NOT NULL,
      reset_at TIMESTAMPTZ NOT NULL
    );
  `);

  // Safe migrations for existing tables
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT FALSE;
  `);
  // Fill email from username for old rows, then make unique+not null
  await pool.query(`
    UPDATE users
       SET email = LOWER(BTRIM(COALESCE(email, username)))
     WHERE email IS NULL OR email <> LOWER(BTRIM(email));
  `);
  await pool.query(`
    ALTER TABLE users ALTER COLUMN email SET NOT NULL;
  `).catch(() => {});

  // Existing installations may have an email column without a uniqueness rule.
  // Fail with a useful message instead of creating an ambiguous login state.
  const duplicateEmails = await pool.query(`
    SELECT email
      FROM users
     GROUP BY email
    HAVING COUNT(*) > 1
     LIMIT 1;
  `);
  if (duplicateEmails.rows.length) {
    throw new Error(`Duplicate email prevents migration: ${duplicateEmails.rows[0].email}`);
  }
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email);
  `);
}

module.exports = { pool, migrate };
