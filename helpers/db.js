require('dotenv').config();
const { Pool } = require('pg');

// buat pool connection
const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// helper query
const query = (text, params) => pool.query(text, params);

module.exports = { query, pool };
