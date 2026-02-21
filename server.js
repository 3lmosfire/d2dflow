const express = require('express');
const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production-' + require('crypto').randomBytes(16).toString('hex');
const DB_PATH = path.join(__dirname, 'd2dflow.db');

let db;

async function initDB() {
    const SQL = await initSqlJs();

    // Load existing database file if it exists
    if (fs.existsSync(DB_PATH)) {
        const buffer = fs.readFileSync(DB_PATH);
        db = new SQL.Database(buffer);
    } else {
        db = new SQL.Database();
    }

    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            flow_data TEXT NOT NULL,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    persistDB();
}

function persistDB() {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// ═══ MIDDLEWARE ═══
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'd2dflow')));

function authenticate(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    try {
        const payload = jwt.verify(header.slice(7), JWT_SECRET);
        req.userId = payload.id;
        req.userEmail = payload.email;
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// ═══ AUTH ROUTES ═══
app.post('/api/auth/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

    const existing = db.exec('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existing.length > 0 && existing[0].values.length > 0) {
        return res.status(409).json({ error: 'Account already exists. Try logging in.' });
    }

    const hash = bcrypt.hashSync(password, 10);
    db.run('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email.toLowerCase(), hash]);
    persistDB();

    const row = db.exec('SELECT last_insert_rowid() as id');
    const userId = row[0].values[0][0];

    const token = jwt.sign({ id: userId, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, email: email.toLowerCase() });
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });

    const result = db.exec('SELECT id, email, password_hash FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!result.length || !result[0].values.length) {
        return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const [userId, userEmail, passwordHash] = result[0].values[0];

    if (!bcrypt.compareSync(password, passwordHash)) {
        return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const token = jwt.sign({ id: userId, email: userEmail }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, email: userEmail });
});

// ═══ FLOW ROUTES ═══
app.get('/api/flow', authenticate, (req, res) => {
    const result = db.exec('SELECT flow_data, updated_at FROM flows WHERE user_id = ?', [req.userId]);
    if (!result.length || !result[0].values.length) {
        return res.json({ flow_data: null });
    }
    const [flowData, updatedAt] = result[0].values[0];
    res.json({ flow_data: flowData, updated_at: updatedAt });
});

app.put('/api/flow', authenticate, (req, res) => {
    const { flow_data } = req.body;
    if (!flow_data) return res.status(400).json({ error: 'flow_data required.' });

    // Validate it's valid JSON
    try { JSON.parse(flow_data); } catch {
        return res.status(400).json({ error: 'flow_data must be valid JSON.' });
    }

    // Upsert: try update first, then insert if no rows affected
    const existing = db.exec('SELECT id FROM flows WHERE user_id = ?', [req.userId]);
    if (existing.length > 0 && existing[0].values.length > 0) {
        db.run('UPDATE flows SET flow_data = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?', [flow_data, req.userId]);
    } else {
        db.run('INSERT INTO flows (user_id, flow_data, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)', [req.userId, flow_data]);
    }
    persistDB();
    res.json({ ok: true });
});

// ═══ SERVE SPA ═══
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'd2dflow', 'index.html'));
});

// ═══ START ═══
initDB().then(() => {
    app.listen(PORT, () => {
        console.log(`D2D Flow server running on http://localhost:${PORT}`);
    });
}).catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
});
