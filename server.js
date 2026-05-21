const express = require('express');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

const app = express();
const db = new Database('database.db');

// Configurations
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'hdx_ultra_secure_secret_key_2026';
const ADMIN_PASSWORD_HASH = bcrypt.hashSync('hdxadmin123', 10); // Change this in production!

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('trust proxy', 1); // Trust reverse proxies like Cloudflare/Nginx for correct IPs

// Initialize Database Tables
db.exec(`
  CREATE TABLE IF NOT EXISTS claim_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    discord_id TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    ip_address TEXT NOT NULL,
    device_fingerprint TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_action TEXT NOT NULL,
    target_code TEXT,
    admin_ip TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Rate Limiters
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests from this IP, please try again later.' }
});

const claimLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 3, 
  message: { error: 'Abuse detection triggered. Too many code requests from this network.' }
});

// Middleware: Authenticate Admin JWT
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access denied. Token missing.' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired session.' });
    req.admin = user;
    next();
  });
};

// Helper: Secure 8-Digit Code Generator
function generateUniqueCode() {
  let attempts = 0;
  while (attempts < 10) {
    const code = Math.floor(10000000 + Math.random() * 90000000).toString();
    const existing = db.prepare('SELECT id FROM claim_requests WHERE code = ?').get(code);
    if (!existing) return code;
    attempts++;
  }
  throw new Error('Failed to generate unique code asset.');
}

/* ================= PUBLIC API ENDPOINTS ================= */

// Anti-Abuse Pre-flight Check
app.post('/api/check-eligibility', globalLimiter, (req, res) => {
  const { fingerprint } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for'];

  if (!fingerprint) return res.status(400).json({ error: 'Missing device parameters.' });

  // 1. Check if IP explicitly blocked
  const isBlocked = db.prepare('SELECT id FROM blocked_ips WHERE ip_address = ?').get(ip);
  if (isBlocked) return res.json({ eligible: false, reason: 'blocked' });

  // 2. Check for duplicate claim by IP or Fingerprint
  const existingClaim = db.prepare(`
    SELECT code, status FROM claim_requests 
    WHERE ip_address = ? OR device_fingerprint = ? LIMIT 1
  `).get(ip, fingerprint);

  if (existingClaim) {
    return res.json({ 
      eligible: false, 
      reason: 'duplicate',
      code: existingClaim.code,
      status: existingClaim.status
    });
  }

  res.json({ eligible: true });
});

// Process Claim Request
app.post('/api/claim', claimLimiter, (req, res) => {
  const { name, email, discord_id, fingerprint } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for'];

  if (!name || !email || !discord_id || !fingerprint) {
    return res.status(400).json({ error: 'All fields are strictly required.' });
  }

  // Double server-side validation check
  const isBlocked = db.prepare('SELECT id FROM blocked_ips WHERE ip_address = ?').get(ip);
  if (isBlocked) return res.status(403).json({ error: 'Device network permanently banned.' });

  const duplicate = db.prepare(`
    SELECT id FROM claim_requests WHERE ip_address = ? OR device_fingerprint = ? LIMIT 1
  `).get(ip, fingerprint);

  if (duplicate) {
    return res.status(409).json({ error: 'You have already claimed a free server from this device or IP.' });
  }

  try {
    const uniqueCode = generateUniqueCode();
    const insert = db.prepare(`
      INSERT INTO claim_requests (name, email, discord_id, code, ip_address, device_fingerprint, status)
      VALUES (?, ?, ?, ?, ?, ?, 'pending')
    `);
    insert.run(name, email, discord_id, uniqueCode, ip, fingerprint);

    res.status(201).json({ success: true, code: uniqueCode });
  } catch (err) {
    res.status(500).json({ error: 'Internal transactional data engine error.' });
  }
});

/* ================= ADMIN MANAGEMENT ENDPOINTS ================= */

// Admin Portal Login
app.post('/api/admin/login', globalLimiter, (req, res) => {
  const { username, password } = req.body;

  if (username !== 'hdxcloudadmin') {
    return res.status(401).json({ error: 'Invalid administrative privileges.' });
  }

  const passwordIsValid = bcrypt.compareSync(password, ADMIN_PASSWORD_HASH);
  if (!passwordIsValid) return res.status(401).json({ error: 'Invalid administrative privileges.' });

  const token = jwt.sign({ user: username }, JWT_SECRET, { expiresIn: '2h' });
  res.json({ success: true, token });
});

// Dashboard Statistics Engine
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) as count FROM claim_requests').get().count;
  const pending = db.prepare("SELECT COUNT(*) as count FROM claim_requests WHERE status = 'pending'").get().count;
  const approved = db.prepare("SELECT COUNT(*) as count FROM claim_requests WHERE status = 'approved'").get().count;
  const rejected = db.prepare("SELECT COUNT(*) as count FROM claim_requests WHERE status = 'rejected'").get().count;
  const used = db.prepare("SELECT COUNT(*) as count FROM claim_requests WHERE status = 'used'").get().count;
  const blocked = db.prepare("SELECT COUNT(*) as count FROM blocked_ips").get().count;

  res.json({ total, pending, approved, rejected, used, blocked });
});

// Fetch and Filter Claims
app.get('/api/admin/claims', authenticateAdmin, (req, res) => {
  const claims = db.prepare('SELECT * FROM claim_requests ORDER BY created_at DESC').all();
  res.json(claims);
});

// Update Status Action (Approve / Reject / Mark Used)
app.post('/api/admin/update-status', authenticateAdmin, (req, res) => {
  const { code, status } = req.body;
  const adminIp = req.ip;

  if (!['pending', 'approved', 'rejected', 'used'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status type assignment.' });
  }

  const stmt = db.prepare("UPDATE claim_requests SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE code = ?");
  const result = stmt.run(status, code);

  if (result.changes > 0) {
    db.prepare("INSERT INTO admin_logs (admin_action, target_code, admin_ip) VALUES (?, ?, ?)")
      .run(`Updated status to ${status}`, code, adminIp);
    return res.json({ success: true });
  }
  res.status(404).json({ error: 'Target claim record code not found.' });
});

// Ban IP Network Node
app.post('/api/admin/block-ip', authenticateAdmin, (req, res) => {
  const { ip_address } = req.body;
  const adminIp = req.ip;

  try {
    db.prepare("INSERT INTO blocked_ips (ip_address) VALUES (?)").run(ip_address);
    db.prepare("INSERT INTO admin_logs (admin_action, target_code, admin_ip) VALUES (?, ?, ?)")
      .run(`Blocked IP Network Address`, ip_address, adminIp);
    res.json({ success: true, message: 'IP address successfully blacklisted.' });
  } catch (err) {
    res.status(400).json({ error: 'IP address already blacklisted or invalid.' });
  }
});

// Delete Record Permanently
app.post('/api/admin/delete-record', authenticateAdmin, (req, res) => {
  const { code } = req.body;
  const adminIp = req.ip;

  const result = db.prepare("DELETE FROM claim_requests WHERE code = ?").run(code);
  if (result.changes > 0) {
    db.prepare("INSERT INTO admin_logs (admin_action, target_code, admin_ip) VALUES (?, ?, ?)")
      .run(`Deleted user claim application data`, code, adminIp);
    return res.json({ success: true });
  }
  res.status(404).json({ error: 'Record could not be localized.' });
});

// Default catch-all router for SPA serving
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`🚀 HDX Cloud Server running dynamically on port ${PORT}`));
