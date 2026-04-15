// ══════════════════════════════════════════════
//  奇门遁甲后端服务 server.js
//  Node.js + Express + SQLite
//  运行：node server.js
// ══════════════════════════════════════════════

const express = require("express");
const cors    = require("cors");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");
const Database = require("better-sqlite3");
const fetch   = require("node-fetch");

const app = express();
const db  = new Database("qimen.db");
const JWT_SECRET  = process.env.JWT_SECRET  || "your-secret-key-change-this";
const CLAUDE_KEY  = process.env.ANTHROPIC_API_KEY || "";
const ADMIN_PASS  = process.env.ADMIN_PASSWORD || "admin888";
const PORT        = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// ── 初始化数据库 ─────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT UNIQUE NOT NULL,
    password  TEXT NOT NULL,
    role      TEXT DEFAULT 'staff',
    enabled   INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );
  CREATE TABLE IF NOT EXISTS logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    username   TEXT,
    question   TEXT,
    matter     TEXT,
    verdict    TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );
`);

// 创建默认管理员账号（首次运行）
const adminExists = db.prepare("SELECT id FROM users WHERE username='admin'").get();
if (!adminExists) {
  const hash = bcrypt.hashSync(ADMIN_PASS, 10);
  db.prepare("INSERT INTO users (username,password,role) VALUES (?,?,?)").run("admin", hash, "admin");
  console.log("✅ 管理员账号已创建：admin / " + ADMIN_PASS);
}

// ── 中间件：验证token ─────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "未登录" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    res.status(401).json({ error: "登录已过期，请重新登录" });
  }
}
function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (req.user.role !== "admin") return res.status(403).json({ error: "无权限" });
    next();
  });
}

// ══════════════════════════════════════════════
//  用户接口
// ══════════════════════════════════════════════

// 登录
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "请填写账号和密码" });
  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username);
  if (!user) return res.status(401).json({ error: "账号不存在" });
  if (!user.enabled) return res.status(403).json({ error: "账号已被停用，请联系管理员" });
  if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "密码错误" });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "8h" });
  res.json({ token, username: user.username, role: user.role });
});

// 获取当前用户信息
app.get("/api/me", auth, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

// ══════════════════════════════════════════════
//  核心：调用 Claude API 生成断语
// ══════════════════════════════════════════════
app.post("/api/duanyu", auth, async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ error: "缺少参数" });
  if (!CLAUDE_KEY) return res.status(500).json({ error: "服务器未配置 API Key" });

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": CLAUDE_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 1000,
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const data = await response.json();
    if (data.error) throw new Error(data.error.message);
    const text = data.content.map(c => c.text || "").join("");
    const clean = text.replace(/```json|```/g, "").trim();
    const result = JSON.parse(clean);

    // 记录日志
    db.prepare("INSERT INTO logs (user_id,username,question,verdict) VALUES (?,?,?,?)").run(
      req.user.id, req.user.username,
      req.body.question || "",
      result.verdict || ""
    );

    res.json(result);
  } catch(e) {
    res.status(500).json({ error: "断语生成失败：" + e.message });
  }
});

// ══════════════════════════════════════════════
//  管理员接口
// ══════════════════════════════════════════════

// 获取所有员工
app.get("/api/admin/users", adminAuth, (req, res) => {
  const users = db.prepare("SELECT id,username,role,enabled,created_at FROM users ORDER BY id").all();
  res.json(users);
});

// 创建员工账号
app.post("/api/admin/users", adminAuth, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "请填写账号和密码" });
  if (username.length < 3) return res.status(400).json({ error: "账号至少3个字符" });
  if (password.length < 6) return res.status(400).json({ error: "密码至少6位" });
  try {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare("INSERT INTO users (username,password,role) VALUES (?,?,'staff')").run(username, hash);
    res.json({ success: true, message: `账号 ${username} 创建成功` });
  } catch(e) {
    if (e.message.includes("UNIQUE")) return res.status(400).json({ error: "账号已存在" });
    res.status(500).json({ error: e.message });
  }
});

// 启用/禁用账号
app.patch("/api/admin/users/:id/toggle", adminAuth, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "用户不存在" });
  if (user.role === "admin") return res.status(400).json({ error: "不能禁用管理员" });
  db.prepare("UPDATE users SET enabled=? WHERE id=?").run(user.enabled ? 0 : 1, user.id);
  res.json({ success: true, enabled: !user.enabled });
});

// 重置密码
app.patch("/api/admin/users/:id/password", adminAuth, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: "密码至少6位" });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare("UPDATE users SET password=? WHERE id=?").run(hash, req.params.id);
  res.json({ success: true });
});

// 删除账号
app.delete("/api/admin/users/:id", adminAuth, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  if (!user) return res.status(404).json({ error: "用户不存在" });
  if (user.role === "admin") return res.status(400).json({ error: "不能删除管理员" });
  db.prepare("DELETE FROM users WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

// 使用记录
app.get("/api/admin/logs", adminAuth, (req, res) => {
  const { username, limit = 50, offset = 0 } = req.query;
  let sql = "SELECT * FROM logs";
  const params = [];
  if (username) { sql += " WHERE username=?"; params.push(username); }
  sql += " ORDER BY id DESC LIMIT ? OFFSET ?";
  params.push(parseInt(limit), parseInt(offset));
  const logs = db.prepare(sql).all(...params);
  const total = db.prepare("SELECT COUNT(*) as n FROM logs" + (username ? " WHERE username=?" : "")).get(...(username ? [username] : []));
  res.json({ logs, total: total.n });
});

// 统计数据
app.get("/api/admin/stats", adminAuth, (req, res) => {
  const total = db.prepare("SELECT COUNT(*) as n FROM logs").get().n;
  const today = db.prepare("SELECT COUNT(*) as n FROM logs WHERE date(created_at)=date('now','localtime')").get().n;
  const users = db.prepare("SELECT COUNT(*) as n FROM users WHERE role='staff'").get().n;
  const active = db.prepare("SELECT COUNT(*) as n FROM users WHERE role='staff' AND enabled=1").get().n;
  const topUsers = db.prepare("SELECT username, COUNT(*) as cnt FROM logs GROUP BY username ORDER BY cnt DESC LIMIT 5").all();
  res.json({ total, today, users, active, topUsers });
});

app.listen(PORT, () => console.log(`✅ 奇门后端运行在 http://localhost:${PORT}`));
