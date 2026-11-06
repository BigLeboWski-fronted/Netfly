require('dotenv').config();
if (process.env.DATABASE_URL_UNPOOLED) process.env.DATABASE_URL = process.env.DATABASE_URL_UNPOOLED;
const { pool, migrate } = require('./db');

migrate()
  .then(() => console.log('Database migrations complete'))
  .catch(error => { console.error(error.message); process.exitCode = 1; })
  .finally(() => pool.end());
