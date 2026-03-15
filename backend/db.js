const mysql = require("mysql2");
require("dotenv").config();

const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 4000),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,

  waitForConnections: true,
  connectionLimit: 20,
  queueLimit: 0,

  ssl: {
    minVersion: "TLSv1.2",
    rejectUnauthorized: true
  },

  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,
  charset: "utf8mb4",
  timezone: "Z",
  connectTimeout: 10000
});

db.getConnection((err, connection) => {
  if (err) {
    console.error("❌ TiDB connection failed:", err.message);
    return;
  }

  console.log("✅ TiDB Connected Successfully");
  connection.release();
});

db.on("error", (err) => {
  console.error("Database Pool Error:", err);
});

module.exports = db;