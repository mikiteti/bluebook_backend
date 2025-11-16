// app.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const knexLib = require('knex');
const { body, param, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const csurf = require('csurf');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'replace_this_in_production';

// ---------- DB (knex with sqlite3) ----------
const knex = knexLib({
    client: 'sqlite3',
    connection: {
        filename: process.env.SQLITE_FILE || path.join(__dirname, 'data.db'),
    },
    useNullAsDefault: true,
    pool: { min: 1, max: 5 },
});

// Initialize DB schema if missing
async function initDb() {
    // users table
    const hasUsers = await knex.schema.hasTable('users');
    if (!hasUsers) {
        await knex.schema.createTable('users', (t) => {
            t.increments('id').primary();
            t.string('username').notNullable().unique();
            t.string('password_hash').notNullable();
            t.timestamp('created_at').defaultTo(knex.fn.now());
        });
        console.log('Created table: users');
    }

    // notes table (example resource)
    const hasNotes = await knex.schema.hasTable('notes');
    if (!hasNotes) {
        await knex.schema.createTable('notes', (t) => {
            t.increments('id').primary();
            t.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
            t.string('title').notNullable();
            t.text('body').notNullable();
            t.timestamp('created_at').defaultTo(knex.fn.now());
            t.timestamp('updated_at').defaultTo(knex.fn.now());
        });
        console.log('Created table: notes');
    }
}

// ---------- Middleware ----------
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Sessions: use SQLite store so session data persists
app.use(session({
    store: new SQLiteStore({
        db: process.env.SESSION_DB || 'sessions.sqlite',
        dir: process.cwd(),
        table: 'sessions', // default
    }),
    name: process.env.SESSION_NAME || 'sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // set true in prod with HTTPS
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
}));

// CSRF protection (for non-API usage or forms). If building a pure JSON API for third-parties you might skip or adapt.
app.use(csurf());

// helper for returning validation errors concisely
function handleValidationErrors(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array().map(e => ({ field: e.param, msg: e.msg })) });
    }
    return null;
}

// simple auth check
function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
}

// ---------- Routes ----------

// GET CSRF token (for forms or frontends to read)
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Register
app.post('/register',
    // validation & sanitization
    body('username').trim().isLength({ min: 3, max: 30 }).withMessage('username 3-30 chars')
        .matches(/^[a-zA-Z0-9_.-]+$/).withMessage('username contains invalid characters'),
    body('password').isLength({ min: 8 }).withMessage('password must be at least 8 chars'),
    async (req, res) => {
        const errRes = handleValidationErrors(req, res);
        if (errRes) return;

        const { username, password } = req.body;
        try {
            const hash = await bcrypt.hash(password, 12);
            // knex parameterizes queries so SQL injection is prevented
            const [id] = await knex('users').insert({ username, password_hash: hash });
            // set session
            req.session.userId = id;
            req.session.username = username;
            res.status(201).json({ id, username });
        } catch (err) {
            if (err && err.code === 'SQLITE_CONSTRAINT') {
                return res.status(409).json({ error: 'username already exists' });
            }
            console.error(err);
            res.status(500).json({ error: 'internal error' });
        }
    }
);

// Login
app.post('/login',
    body('username').trim().notEmpty(),
    body('password').notEmpty(),
    async (req, res) => {
        const errRes = handleValidationErrors(req, res);
        if (errRes) return;

        const { username, password } = req.body;
        try {
            const user = await knex('users').where({ username }).first();
            if (!user) return res.status(401).json({ error: 'invalid credentials' });

            const ok = await bcrypt.compare(password, user.password_hash);
            if (!ok) return res.status(401).json({ error: 'invalid credentials' });

            req.session.userId = user.id;
            req.session.username = user.username;
            res.json({ message: 'ok', id: user.id, username: user.username });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'internal error' });
        }
    }
);

// Logout
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'could not log out' });
        }
        res.clearCookie(process.env.SESSION_NAME || 'sid');
        res.json({ message: 'logged out' });
    });
});

// Get current user
app.get('/me', (req, res) => {
    if (!req.session || !req.session.userId) return res.status(200).json({ user: null });
    res.json({ user: { id: req.session.userId, username: req.session.username } });
});

// ------- Example resource: notes (CRUD) -------
/*
  Notes belong to a user. All queries use knex (parameterized).
  Inputs are validated & sanitized via express-validator.
*/

// Create note
app.post('/notes',
    requireAuth,
    body('title').trim().isLength({ min: 1, max: 200 }).withMessage('title required 1-200 chars'),
    body('body').trim().isLength({ min: 1 }).withMessage('body required'),
    async (req, res) => {
        const errRes = handleValidationErrors(req, res);
        if (errRes) return;

        const { title, body: noteBody } = req.body;
        try {
            const [id] = await knex('notes').insert({
                user_id: req.session.userId,
                title,
                body: noteBody
            });
            const created = await knex('notes').where({ id }).first();
            res.status(201).json(created);
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'internal error' });
        }
    }
);

// Read user's notes (list)
app.get('/notes', requireAuth, async (req, res) => {
    try {
        const notes = await knex('notes').where({ user_id: req.session.userId }).orderBy('created_at', 'desc');
        res.json({ notes });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'internal error' });
    }
});

// Read single note (ensures ownership)
app.get('/notes/:id',
    requireAuth,
    param('id').isInt().toInt(),
    async (req, res) => {
        const errRes = handleValidationErrors(req, res);
        if (errRes) return;

        const id = Number(req.params.id);
        try {
            const note = await knex('notes').where({ id, user_id: req.session.userId }).first();
            if (!note) return res.status(404).json({ error: 'not found' });
            res.json(note);
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'internal error' });
        }
    }
);

// Update note (partial)
app.patch('/notes/:id',
    requireAuth,
    param('id').isInt().toInt(),
    body('title').optional().trim().isLength({ min: 1, max: 200 }),
    body('body').optional().trim().isLength({ min: 1 }),
    async (req, res) => {
        const errRes = handleValidationErrors(req, res);
        if (errRes) return;

        const id = Number(req.params.id);
        const toUpdate = {};
        if (req.body.title !== undefined) toUpdate.title = req.body.title;
        if (req.body.body !== undefined) toUpdate.body = req.body.body;
        if (Object.keys(toUpdate).length === 0) return res.status(400).json({ error: 'nothing to update' });

        toUpdate.updated_at = knex.fn.now();

        try {
            const updated = await knex('notes').where({ id, user_id: req.session.userId }).update(toUpdate);
            if (!updated) return res.status(404).json({ error: 'not found or not owner' });
            const note = await knex('notes').where({ id }).first();
            res.json(note);
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'internal error' });
        }
    }
);

// Delete note
app.delete('/notes/:id',
    requireAuth,
    param('id').isInt().toInt(),
    async (req, res) => {
        const errRes = handleValidationErrors(req, res);
        if (errRes) return;

        const id = Number(req.params.id);
        try {
            const deleted = await knex('notes').where({ id, user_id: req.session.userId }).del();
            if (!deleted) return res.status(404).json({ error: 'not found or not owner' });
            res.json({ success: true });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'internal error' });
        }
    }
);

// ---------- Error handling ----------
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        // CSRF token errors
        return res.status(403).json({ error: 'invalid CSRF token' });
    }
    console.error('Unhandled error', err);
    res.status(500).json({ error: 'internal error' });
});

// ---------- Start ----------
(async () => {
    try {
        await initDb();
        app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT} (NODE_ENV=${process.env.NODE_ENV || 'development'})`);
        });
    } catch (err) {
        console.error('Failed to start', err);
        process.exit(1);
    }
})();
