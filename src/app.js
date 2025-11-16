const express = require("express");
const cors = require('cors');
const Database = require("better-sqlite3");
const session = require("express-session");
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
app.use(cors({
    origin: "http://localhost:53926",
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
    session({
        store: new SQLiteStore({
            db: 'sessions.sqlite', // SQLite DB file
            dir: './data',           // optional, folder to store db
            ttl: 86400 // seconds = 1 day
            // table: 'sessions',  // optional, default table name
        }),
        secret: 'secret', // change this to a strong secret
        resave: false,                  // don't save session if unmodified
        saveUninitialized: true,       // only save sessions when something stored
        cookie: {
            maxAge: 1000 * 60 * 60 * 24, // 1 day
            httpOnly: true,               // prevents client-side JS access
        },
    })
);

const db = new Database("data/derive.sqlite");

const generateNewUrl = (table) => {
    let abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let url = "";
    for (let i = 0; i < 10; i++) url += abc[Math.floor(Math.random() * abc.length)];
    const alreadyExists = db.prepare("SELECT id FROM " + table + " WHERE url = ?").get(url);
    if (alreadyExists) return generateNewUrl(table);
    return url;
}

app.listen(3000, () => {
    console.log(`Server running on port 3000`);
});

app.get("/", (req, res) => {
    res.json({ welcomeMessage: "Hello world!" });
});

app.post("/new_user", (req, res) => {
    const { email, name, password } = req.body;
    if (email == undefined) return res.status(400).send('Email is required');
    if (name == undefined) return res.status(400).send('Name is required');
    if (password == undefined) return res.status(400).send('Password is required');

    try {
        db.prepare("INSERT INTO users (email, name, password) VALUES (?, ?, ?)").run(email, name, password);
    } catch (e) {
        if (e.code === "SQLITE_CONSTRAINT_UNIQUE") {
            res.status(400).send('Email already exists');
            return;
        }
    }

    res.status(200).send("User added");
})

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    if (email == undefined) return res.status(400).send('Email is required.');
    if (password == undefined) return res.status(400).send('Password is required.');
    const user = db.prepare("SELECT id, password FROM users WHERE email = ?").get(email);

    if (!user) return res.status(401).send('User not found');
    if (user.password !== password) return res.status(401).send('Wrong password');

    // Store user info in session
    req.session.userId = user.id;
    res.send(`Logged in`);
});

app.get("/user", (req, res) => {
    if (!req.session.userId) return res.status(401).send('Not logged in');
    res.json(db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId));
});

app.get("/notes", (req, res) => {
    if (!req.session.userId) return res.status(401).send('Not logged in');
    const notes = db.prepare("SELECT id, url, name, user_id, misc FROM notes WHERE user_id = ?").all(req.session.userId);
    res.json(notes);
});

app.post("/note", (req, res) => {
    if (!req.session.userId) return res.status(401).send('Not logged in');

    const { id } = req.body;
    if (id == undefined) return res.status(400).send('Id is required.');

    const note = db.prepare("SELECT * FROM notes WHERE id = ?").get(id);
    if (note.user_id !== req.session.userId) return res.status(403).send('Not your note');

    res.json(note);
});

app.post("/new_note", (req, res) => {
    if (!req.session.userId) return res.status(401).send('Not logged in');

    const { name } = req.body;
    if (name == undefined) return res.status(400).send('Name is required');
    const alreadyExists = db.prepare("SELECT name FROM notes WHERE user_id = ? AND name = ?").get(req.session.userId, name);
    if (alreadyExists) return res.status(400).send("File already exists");

    const note = db.prepare("INSERT INTO notes (name, url, user_id) VALUES (?, ?, ?)").run(name, generateNewUrl('notes'), req.session.userId);
    res.json({ id: note.lastInsertRowid });
});

app.post("/update_note", (req, res) => {
    if (!req.session.userId) return res.status(401).send('Not logged in');

    const { content, name, misc, id } = req.body;
    if (id == undefined) return res.status(400).send('Id is required.');

    const note = db.prepare("SELECT user_id FROM notes WHERE id = ?").get(id);
    if (note == undefined) return res.status(400).send("Note doesn't exist");
    if (note.user_id !== req.session.userId) return res.status(403).send("Not your note");

    try {
        if (content) db.prepare("UPDATE notes SET content = ? WHERE id = ?").run(content, id);
        if (name) db.prepare("UPDATE notes SET name = ? WHERE id = ?").run(name, id);
        if (misc) db.prepare("UPDATE notes SET misc = ? WHERE id = ?").run(misc, id);
    } catch (e) {
        return res.status(400).send("Something went wrong");
    }

    res.send("Note updated");
});
