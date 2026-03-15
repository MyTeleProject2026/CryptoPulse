const mysql = require("mysql2");
require("dotenv").config();

/* =================================
   MYSQL CONNECTION POOL
================================= */

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,

  waitForConnections: true,
  connectionLimit: 25,
  queueLimit: 0,

  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,

  charset: "utf8mb4",
  timezone: "Z",

  connectTimeout: 10000
});

/* =================================
   CONNECTION TEST
================================= */

pool.getConnection((err, connection) => {

  if (err) {
    console.error("❌ MySQL connection failed:", err.message);

    if (err.code === "PROTOCOL_CONNECTION_LOST") {
      console.error("Database connection lost.");
    }

    if (err.code === "ER_CON_COUNT_ERROR") {
      console.error("Database has too many connections.");
    }

    if (err.code === "ECONNREFUSED") {
      console.error("Database connection refused.");
    }

    return;
  }

  if (connection) {
    console.log("✅ MySQL Connected Successfully");
    connection.release();
  }

});

/* =================================
   POOL ERROR LISTENER
================================= */

pool.on("error", (err) => {
  console.error("MySQL Pool Error:", err);
});

/* =================================
   HEALTH CHECK FUNCTION
================================= */

function checkDatabaseHealth() {

  pool.query("SELECT 1", (err) => {

    if (err) {
      console.error("⚠️ Database health check failed:", err.message);
    } else {
      console.log("🟢 Database healthy");
    }

  });

}

/* run health check every 5 minutes */
setInterval(checkDatabaseHealth, 300000);

/* =================================
   OPTIONAL QUERY LOGGER
================================= */

if (process.env.NODE_ENV !== "production") {

  const originalQuery = pool.query;

  pool.query = function (...args) {

    console.log("SQL Query:", args[0]);

    return originalQuery.apply(pool, args);

  };

}

/* =================================
   EXPORT DATABASE
================================= */

module.exports = pool;