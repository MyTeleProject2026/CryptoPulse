const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
require("dotenv").config();
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET missing in .env");
}

/* =========================================
   APP MIDDLEWARE
========================================= */

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

/* =========================================
   RATE LIMITERS
========================================= */

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: "Too many login attempts. Try later." },
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: "Too many admin login attempts. Try later." },
});

const tradeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { message: "Too many trades. Slow down." },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
});

app.use(apiLimiter);

/* =========================================
   TOKEN SETTINGS
========================================= */

const ACCESS_TOKEN_EXPIRES = "15m";
const REFRESH_TOKEN_DAYS = 7;

function generateAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRES,
  });
}

function generateRefreshToken() {
  return jwt.sign(
    { type: "refresh", rand: Math.random().toString(36).slice(2) },
    JWT_SECRET,
    { expiresIn: `${REFRESH_TOKEN_DAYS}d` }
  );
}

/* =========================================
   HELPERS
========================================= */

const ALLOWED_COINS = ["BTC", "ETH", "USDT"];
const ALLOWED_NETWORKS = ["TRC20", "ERC20", "BEP20"];

function isValidCoin(coin) {
  return ALLOWED_COINS.includes(String(coin || "").toUpperCase());
}

function isValidNetwork(network) {
  return ALLOWED_NETWORKS.includes(String(network || "").toUpperCase());
}

/* =========================================
   AUTH MIDDLEWARE
========================================= */

function authenticateToken(req, res, next) {
  const header = req.headers.authorization;
  const token = header && header.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access denied" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
}

function authenticateUser(req, res, next) {
  authenticateToken(req, res, () => {
    if (req.user.role !== "user") {
      return res.status(403).json({ message: "User only" });
    }
    next();
  });
}

function authenticateAdmin(req, res, next) {
  authenticateToken(req, res, () => {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Admin only" });
    }
    next();
  });
}

/* =========================================
   BINANCE PRICE HELPER
========================================= */

async function getBinancePrice(symbol) {
  try {
    const response = await axios.get(
      "https://api.binance.com/api/v3/ticker/price",
      {
        params: { symbol },
        timeout: 5000,
      }
    );

    if (!response.data || !response.data.price) {
      throw new Error("Invalid price response");
    }

    return Number(response.data.price);
  } catch (err) {
    console.error("Binance price error:", err.message);
    throw new Error("Market price unavailable");
  }
}

/* =========================================
   TRADE CLOSING ENGINE
========================================= */

async function closeTrade(trade) {
  try {
    const closePrice = await getBinancePrice(trade.pair);

    let result = "lose";
    let payout = 0;

    const amount = Number(trade.amount);
    const entry = Number(trade.entry_price);
    const percent = Number(trade.profit_percent);

    if (
      (trade.direction === "bullish" && closePrice > entry) ||
      (trade.direction === "bearish" && closePrice < entry)
    ) {
      payout = amount + (amount * percent) / 100;
      result = "win";

      db.query(
        "UPDATE users SET balance = balance + ? WHERE id = ?",
        [payout, trade.user_id],
        (err) => {
          if (err) {
            console.error("User balance update error:", err.message);
          }
        }
      );
    }

    db.query(
      "UPDATE trades SET result=?, status='closed', close_price=?, closed_at=NOW() WHERE id=?",
      [result, closePrice, trade.id],
      (err) => {
        if (err) {
          console.error("Trade update error:", err.message);
        }
      }
    );
  } catch (err) {
    console.error("Trade close error:", err.message);
  }
}

function processOpenTrades() {
  db.query(
    "SELECT * FROM trades WHERE status='open' AND end_time <= NOW() LIMIT 20",
    async (err, trades) => {
      if (err) {
        console.error("Trade scan error:", err.message);
        return;
      }

      for (const trade of trades) {
        await closeTrade(trade);
      }
    }
  );
}

/* =========================================
   CLEAN EXPIRED TOKENS
========================================= */

function cleanExpiredTokens() {
  db.query(
    "DELETE FROM refresh_tokens WHERE expires_at < NOW()",
    (err) => {
      if (err) {
        console.error("Token cleanup error:", err.message);
      }
    }
  );
}

/* =========================================
   BASIC ROUTES
========================================= */

app.get("/", (req, res) => {
  res.send("CryptoPulse API Running 🚀");
});

app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    uptime: process.uptime(),
    timestamp: new Date(),
  });
});

/* =========================================
   USER REGISTER
========================================= */

app.post("/register", async (req, res) => {
  try {
    let { name, email, password, confirmPassword } = req.body;

    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({ message: "All fields required" });
    }

    name = String(name).trim();
    email = String(email).trim().toLowerCase();

    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({ message: "All fields required" });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ message: "Passwords mismatch" });
    }

    const hash = await bcrypt.hash(password, 10);

    db.query(
      "INSERT INTO users (name,email,password,status) VALUES (?,?,?, 'active')",
      [name, email, hash],
      (err) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") {
            return res.status(400).json({ message: "Email exists" });
          }
          return res.status(500).json({ error: err.message });
        }

        res.json({ message: "User registered successfully" });
      }
    );
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================================
   USER LOGIN
========================================= */

app.post("/login", loginLimiter, (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password required" });
  }

  db.query(
    "SELECT * FROM users WHERE email=? LIMIT 1",
    [String(email).trim().toLowerCase()],
    async (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });

      if (!rows || rows.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const user = rows[0];
      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return res.status(400).json({ message: "Invalid password" });
      }

      const accessToken = generateAccessToken({
        id: user.id,
        role: "user",
      });

      const refreshToken = generateRefreshToken();

      const expires = new Date(
        Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000
      );

      db.query(
        "INSERT INTO refresh_tokens (user_id,token,expires_at) VALUES (?,?,?)",
        [user.id, refreshToken, expires],
        (tokenErr) => {
          if (tokenErr) {
            return res.status(500).json({ error: tokenErr.message });
          }

          res.json({
            message: "Login successful",
            accessToken,
            refreshToken,
            user: {
              id: user.id,
              name: user.name,
              email: user.email,
              balance: user.balance,
            },
          });
        }
      );
    }
  );
});

/* =========================================
   ADMIN LOGIN
   Assumes admins table has:
   id, username, password
========================================= */

app.post("/admin/login", adminLoginLimiter, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  db.query(
    "SELECT * FROM admins WHERE username=? LIMIT 1",
    [String(username).trim()],
    async (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });

      if (!rows || rows.length === 0) {
        return res.status(404).json({ message: "Admin not found" });
      }

      const admin = rows[0];
      const match = await bcrypt.compare(password, admin.password);

      if (!match) {
        return res.status(400).json({ message: "Invalid password" });
      }

      const accessToken = generateAccessToken({
        id: admin.id,
        role: "admin",
      });

      res.json({
        message: "Admin login successful",
        accessToken,
        admin: {
          id: admin.id,
          username: admin.username,
        },
      });
    }
  );
});

/* =========================================
   DEPOSIT WALLET ADDRESSES
   Table needed:

   CREATE TABLE deposit_wallets (
     id INT AUTO_INCREMENT PRIMARY KEY,
     coin ENUM('BTC','ETH','USDT') NOT NULL,
     network ENUM('TRC20','ERC20','BEP20') NOT NULL,
     address VARCHAR(255) NOT NULL,
     status ENUM('active','inactive') DEFAULT 'active',
     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );
========================================= */

/* Public/User: view active deposit addresses */
app.get("/deposit-addresses", (req, res) => {
  const { coin, network } = req.query;

  let sql =
    "SELECT id, coin, network, address, status, created_at FROM deposit_wallets WHERE status='active'";
  const params = [];

  if (coin) {
    sql += " AND coin=?";
    params.push(String(coin).toUpperCase());
  }

  if (network) {
    sql += " AND network=?";
    params.push(String(network).toUpperCase());
  }

  sql += " ORDER BY coin ASC, network ASC";

  db.query(sql, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

/* Admin: create deposit wallet address */
app.post("/admin/deposit-wallets", authenticateAdmin, (req, res) => {
  const { coin, network, address, status } = req.body;

  const safeCoin = String(coin || "").toUpperCase();
  const safeNetwork = String(network || "").toUpperCase();
  const safeStatus = String(status || "active").toLowerCase();

  if (!isValidCoin(safeCoin)) {
    return res.status(400).json({ message: "Invalid coin" });
  }

  if (!isValidNetwork(safeNetwork)) {
    return res.status(400).json({ message: "Invalid network" });
  }

  if (!address || String(address).trim().length < 8) {
    return res.status(400).json({ message: "Valid wallet address required" });
  }

  if (!["active", "inactive"].includes(safeStatus)) {
    return res.status(400).json({ message: "Invalid wallet status" });
  }

  db.query(
    "INSERT INTO deposit_wallets (coin, network, address, status) VALUES (?, ?, ?, ?)",
    [safeCoin, safeNetwork, String(address).trim(), safeStatus],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      res.json({
        message: "Deposit wallet created successfully",
        walletId: result.insertId,
      });
    }
  );
});

/* Admin: list all deposit wallet addresses */
app.get("/admin/deposit-wallets", authenticateAdmin, (req, res) => {
  db.query(
    "SELECT * FROM deposit_wallets ORDER BY id DESC",
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

/* Admin: update deposit wallet address status/address */
app.put("/admin/deposit-wallets/:id", authenticateAdmin, (req, res) => {
  const walletId = req.params.id;
  const { address, status } = req.body;

  if (!address && !status) {
    return res.status(400).json({ message: "Nothing to update" });
  }

  const fields = [];
  const values = [];

  if (address) {
    fields.push("address=?");
    values.push(String(address).trim());
  }

  if (status) {
    const safeStatus = String(status).toLowerCase();
    if (!["active", "inactive"].includes(safeStatus)) {
      return res.status(400).json({ message: "Invalid status" });
    }
    fields.push("status=?");
    values.push(safeStatus);
  }

  values.push(walletId);

  db.query(
    `UPDATE deposit_wallets SET ${fields.join(", ")} WHERE id=?`,
    values,
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Wallet not found" });
      }

      res.json({ message: "Deposit wallet updated successfully" });
    }
  );
});

/* =========================================
   USER DEPOSIT ROUTES
   Table needed:

   CREATE TABLE deposits (
     id INT AUTO_INCREMENT PRIMARY KEY,
     user_id INT NOT NULL,
     coin ENUM('BTC', 'ETH', 'USDT') NOT NULL,
     network ENUM('TRC20', 'ERC20', 'BEP20') NOT NULL,
     amount DECIMAL(18,8) NOT NULL,
     txid VARCHAR(255) DEFAULT NULL,
     proof_image VARCHAR(255) DEFAULT NULL,
     status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
     admin_note TEXT DEFAULT NULL,
     approved_by INT DEFAULT NULL,
     approved_at DATETIME DEFAULT NULL,
     rejected_at DATETIME DEFAULT NULL,
     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );
========================================= */

/* User: submit deposit request */
app.post("/deposit", authenticateUser, (req, res) => {
  const { coin, network, amount, txid, proof_image } = req.body;

  const safeCoin = String(coin || "").toUpperCase();
  const safeNetwork = String(network || "").toUpperCase();
  const depositAmount = Number(amount);

  if (!isValidCoin(safeCoin)) {
    return res.status(400).json({ message: "Invalid coin" });
  }

  if (!isValidNetwork(safeNetwork)) {
    return res.status(400).json({ message: "Invalid network" });
  }

  if (!depositAmount || depositAmount <= 0) {
    return res.status(400).json({ message: "Invalid amount" });
  }

  db.query(
    `INSERT INTO deposits
     (user_id, coin, network, amount, txid, proof_image, status)
     VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
    [
      req.user.id,
      safeCoin,
      safeNetwork,
      depositAmount,
      txid ? String(txid).trim() : null,
      proof_image ? String(proof_image).trim() : null,
    ],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      res.json({
        message: "Deposit request submitted successfully",
        depositId: result.insertId,
        status: "pending",
      });
    }
  );
});

/* User: view own deposits */
app.get("/my-deposits", authenticateUser, (req, res) => {
  db.query(
    "SELECT * FROM deposits WHERE user_id=? ORDER BY id DESC",
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

/* =========================================
   ADMIN DEPOSIT MANAGEMENT
========================================= */

/* Admin: view all deposits */
app.get("/admin/deposits", authenticateAdmin, (req, res) => {
  db.query(
    `SELECT d.*, u.name, u.email
     FROM deposits d
     JOIN users u ON d.user_id = u.id
     ORDER BY d.id DESC`,
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

/* Admin: approve deposit
   Transaction prevents balance update without status update
*/
app.post("/admin/deposits/:id/approve", authenticateAdmin, (req, res) => {
  const depositId = req.params.id;
  const adminId = req.user.id;

  db.beginTransaction((txErr) => {
    if (txErr) {
      return res.status(500).json({ error: txErr.message });
    }

    db.query(
      "SELECT * FROM deposits WHERE id=? AND status='pending' LIMIT 1",
      [depositId],
      (selectErr, rows) => {
        if (selectErr) {
          return db.rollback(() =>
            res.status(500).json({ error: selectErr.message })
          );
        }

        if (!rows || rows.length === 0) {
          return db.rollback(() =>
            res.status(404).json({ message: "Pending deposit not found" })
          );
        }

        const deposit = rows[0];

        db.query(
          `UPDATE deposits
           SET status='approved', approved_by=?, approved_at=NOW()
           WHERE id=? AND status='pending'`,
          [adminId, depositId],
          (updateErr, updateResult) => {
            if (updateErr) {
              return db.rollback(() =>
                res.status(500).json({ error: updateErr.message })
              );
            }

            if (updateResult.affectedRows === 0) {
              return db.rollback(() =>
                res.status(400).json({ message: "Deposit already processed" })
              );
            }

            db.query(
              "UPDATE users SET balance = balance + ? WHERE id=?",
              [deposit.amount, deposit.user_id],
              (balanceErr, balanceResult) => {
                if (balanceErr) {
                  return db.rollback(() =>
                    res.status(500).json({ error: balanceErr.message })
                  );
                }

                if (balanceResult.affectedRows === 0) {
                  return db.rollback(() =>
                    res.status(404).json({ message: "User not found" })
                  );
                }

                db.query(
                  `INSERT INTO transactions (user_id, type, amount, status)
                   VALUES (?, 'deposit', ?, 'approved')`,
                  [deposit.user_id, deposit.amount],
                  (trxErr) => {
                    if (trxErr) {
                      return db.rollback(() =>
                        res.status(500).json({ error: trxErr.message })
                      );
                    }

                    db.commit((commitErr) => {
                      if (commitErr) {
                        return db.rollback(() =>
                          res.status(500).json({ error: commitErr.message })
                        );
                      }

                      res.json({
                        message: "Deposit approved successfully",
                        depositId: Number(depositId),
                        userId: deposit.user_id,
                        amount: deposit.amount,
                      });
                    });
                  }
                );
              }
            );
          }
        );
      }
    );
  });
});

/* Admin: reject deposit */
app.post("/admin/deposits/:id/reject", authenticateAdmin, (req, res) => {
  const depositId = req.params.id;
  const { admin_note } = req.body;

  db.query(
    `UPDATE deposits
     SET status='rejected', admin_note=?, rejected_at=NOW()
     WHERE id=? AND status='pending'`,
    [admin_note ? String(admin_note).trim() : null, depositId],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Pending deposit not found" });
      }

      res.json({ message: "Deposit rejected successfully" });
    }
  );
});

/* =========================================
   USER PLACE TRADE
========================================= */

app.post("/trade", tradeLimiter, authenticateUser, async (req, res) => {
  const { pair, direction, amount, timer } = req.body;
  const userId = req.user.id;

  if (!pair || !direction || !amount || !timer) {
    return res.status(400).json({ message: "Missing trade fields" });
  }

  if (!["bullish", "bearish"].includes(direction)) {
    return res.status(400).json({ message: "Invalid direction" });
  }

  if (Number(amount) <= 0 || Number(timer) <= 0) {
    return res.status(400).json({
      message: "Amount and timer must be positive",
    });
  }

  try {
    const entryPrice = await getBinancePrice(pair);

    db.query("SELECT balance FROM users WHERE id=?", [userId], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });

      if (!rows || rows.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const balance = Number(rows[0].balance);
      const tradeAmount = Number(amount);
      const tradeTimer = Number(timer);

      if (balance < tradeAmount) {
        return res.status(400).json({ message: "Insufficient balance" });
      }

      db.query(
        "UPDATE users SET balance = balance - ? WHERE id=?",
        [tradeAmount, userId],
        (updateErr) => {
          if (updateErr) {
            return res.status(500).json({ error: updateErr.message });
          }

          db.query(
            `INSERT INTO trades
            (user_id,pair,direction,amount,entry_price,timer,profit_percent,result,status,end_time)
            VALUES (?,?,?,?,?,?,10,'pending','open',DATE_ADD(NOW(), INTERVAL ? SECOND))`,
            [
              userId,
              pair,
              direction,
              tradeAmount,
              entryPrice,
              tradeTimer,
              tradeTimer,
            ],
            (insertErr) => {
              if (insertErr) {
                return res.status(500).json({ error: insertErr.message });
              }

              res.json({
                message: "Trade placed",
                entryPrice,
              });
            }
          );
        }
      );
    });
  } catch (err) {
    res.status(500).json({ message: "Price unavailable" });
  }
});

/* =========================================
   404
========================================= */

app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

/* =========================================
   GLOBAL ERROR HANDLER
========================================= */

app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ message: "Internal server error" });
});

/* =========================================
   BACKGROUND JOBS
========================================= */

setInterval(processOpenTrades, 5000);
setInterval(cleanExpiredTokens, 60 * 60 * 1000);

/* =========================================
   SERVER START
========================================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`CryptoPulse running on port ${PORT}`);
});