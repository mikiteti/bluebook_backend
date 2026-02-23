const express = require("express");
const cors = require('cors');
const Database = require("better-sqlite3");
const session = require("express-session");
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require("bcrypt");
const { spawn } = require("node:child_process");
require('dotenv').config();

const app = express();
app.use(cors({
    origin: process.env.ALLOW,
    credentials: true
}));
// app.use(cors({
//     origin: (origin, callback) => {
//         if (!origin) return callback(null, true);
//
//         if (origin === process.env.ALLOW) return callback(null, true);
//         if (origin.startsWith("http://localhost") || origin.startsWith("http://127.0.0.1")) return callback(null, true);
//
//         return callback(new Error("Not allowed by CORS"));
//     },
//     credentials: true
// }));
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
        secret: process.env.SECRET, // change this to a strong secret
        resave: false,                  // don't save session if unmodified
        saveUninitialized: true,       // only save sessions when something stored
        cookie: {
            maxAge: 1000 * 60 * 60 * 24, // 1 day
            httpOnly: true,               // prevents client-side JS access
        },
    })
);

const db = new Database("data/bluebook.sqlite");
console.log("Connected to db: ", db);

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

app.post("/new_user", async (req, res) => {
    const { email, name, password } = req.body;
    if (email == undefined) return res.status(400).send('Email is required');
    if (name == undefined) return res.status(400).send('Name is required');
    if (password == undefined) return res.status(400).send('Password is required');
    const hashed = await bcrypt.hash(password, 12);

    try {
        db.prepare("INSERT INTO users (email, name, password) VALUES (?, ?, ?)").run(email, name, hashed);
    } catch (e) {
        if (e.code === "SQLITE_CONSTRAINT_UNIQUE") {
            res.status(400).send('Email already exists');
            return;
        }
    }

    res.status(200).send("User added");
})

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (email == undefined) return res.status(400).send('Email is required.');
    if (password == undefined) return res.status(400).send('Password is required.');
    const user = db.prepare("SELECT id, password FROM users WHERE email = ?").get(email);

    if (!user) return res.status(401).send('User not found');
    if (!await bcrypt.compare(password, user.password)) return res.status(401).send('Wrong password');

    // Store user info in session
    req.session.userId = user.id;
    res.send(`Logged in`);
});

app.get("/user", (req, res) => {
    if (!req.session.userId) return res.status(401).send('Not logged in');
    res.json(db.prepare("SELECT id, email, name, misc FROM users WHERE id = ?").get(req.session.userId));
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

app.post("/note_by_url", (req, res) => {
    const { url } = req.body;
    if (url == undefined) return res.status(400).send('Url is required');

    const note = db.prepare("SELECT * FROM notes WHERE url = ?").get(url);
    if (note == undefined) return res.status(400).send('Note not found');

    res.json(note);
});

app.post("/new_note", (req, res) => {
    if (!req.session.userId) return res.status(401).send('Not logged in');

    const { name } = req.body;
    if (name == undefined) return res.status(400).send('Name is required');
    // const alreadyExists = db.prepare("SELECT name FROM notes WHERE user_id = ? AND name = ?").get(req.session.userId, name);
    // if (alreadyExists) return res.status(400).send("File already exists");

    const note = db.prepare("INSERT INTO notes (name, url, user_id, content) VALUES (?, ?, ?, ?)").run(name, generateNewUrl('notes'), req.session.userId, JSON.stringify([]));
    res.json({ id: note.lastInsertRowid });
});

app.post("/update_note", (req, res) => {
    if (!req.session.userId) return res.status(401).send('Not logged in');

    let { content, name, misc, id } = req.body;
    if (id == undefined) return res.status(400).send('Id is required.');

    const note = db.prepare("SELECT user_id FROM notes WHERE id = ?").get(id);
    if (note == undefined) return res.status(400).send("Note doesn't exist");
    if (note.user_id !== req.session.userId) return res.status(403).send("Not your note");

    try {
        if (content) db.prepare("UPDATE notes SET content = ? WHERE id = ?").run(content, id);
        if (name) db.prepare("UPDATE notes SET name = ? WHERE id = ?").run(name, id);
        if (misc) {
            const currentMisc = db.prepare("SELECT misc FROM notes WHERE id = ?").get(id).misc;
            misc = JSON.stringify({ ...JSON.parse(currentMisc), ...JSON.parse(misc) });
            db.prepare("UPDATE notes SET misc = ? WHERE id = ?").run(misc, id);
        }
    } catch (e) {
        return res.status(400).send("Something went wrong");
    }

    res.send("Note updated");
});

// app.post("/convert/pdf", express.raw({ type: "*/*", limit: "10mb" }), (req, res) => {
//     console.log("converting to pdf");
//     res.setHeader("Content-Type", "application/pdf");
//
//     const pandoc = spawn("pandoc", [
//         "-f", "markdown",
//         "-t", "pdf",
//         // "--include-in-header=/opt/pandoc/preamble.tex",
//         "-o", "-"
//     ]);
//
//     req.pipe(pandoc.stdin);
//     pandoc.stdout.pipe(res);
//
//     pandoc.stderr.on("data", d => console.error(d.toString()));
// });

app.get("/attachments", (req, res) => {
    if (!req.session.userId) return res.status(401).send('Not logged in');
    const attachments = db.prepare("SELECT id, url, user_id, type, misc FROM attachments WHERE user_id = ?").all(req.session.userId);
    res.json(attachments);
});

app.post("/attachment/meta", (req, res) => { // used when listing attachments (together with view)
    const { url } = req.body;
    if (url == undefined) return res.status(400).send('Url is required');

    const attachment = db.prepare("SELECT id, url, user_id, type, created, misc FROM attachments WHERE url = ?").get(url);
    if (attachment == undefined) return res.status(400).send('Attachment not found');

    res.json(attachment);
});

app.post("/attachment/content", (req, res) => { // used before editing an attachment
    const { url } = req.body;
    if (url == undefined) return res.status(400).send('Url is required');

    const attachment = db.prepare("SELECT id, url, user_id, type, created, misc, content FROM attachments WHERE url = ?").get(url);
    if (attachment == undefined) return res.status(404).send('Attachment not found');

    console.log({ attachment });
    res.json(attachment);
});

app.post("/attachment/all", (req, res) => { // just for the sake of completeness
    const { url } = req.body;
    if (url == undefined) return res.status(400).send('Url is required');

    const attachment = db.prepare("SELECT * FROM attachments WHERE url = ?").get(url);
    if (attachment == undefined) return res.status(400).send('Attachment not found');

    res.json(attachment);
});

app.post("/new_attachment", (req, res) => {
    if (!req.session.userId) return res.status(401).send('Not logged in');

    let { type } = req.body;
    if (type == undefined) return res.status(400).send('Type is required.');
    if (!["graph", "geometry", "sketch"].includes(type)) return res.status(400).send('Type needs to be graph, geometry or sketch.');

    const url = generateNewUrl('attachments');
    const attachment = db.prepare("INSERT INTO attachments (url, user_id, type, preview, content) VALUES (?, ?, ?, ?, ?)").run(url, req.session.userId, type, "", JSON.stringify([]));
    res.json({ url });
});

app.post("/update_attachment", (req, res) => {
    if (!req.session.userId) return res.status(401).send('Not logged in');

    let { content, preview, misc, url } = req.body;
    if (url == undefined) return res.status(400).send('Url is required.');

    const attachment = db.prepare("SELECT user_id FROM attachments WHERE url = ?").get(url);
    if (attachment == undefined) return res.status(400).send("Attachment doesn't exist");
    if (attachment.user_id !== req.session.userId) return res.status(403).send("Not your attachment");

    try {
        if (content) db.prepare("UPDATE attachments SET content = ? WHERE url = ?").run(content, url);
        if (preview) db.prepare("UPDATE attachments SET preview = ? WHERE url = ?").run(preview, url);
        if (misc) {
            const currentMisc = db.prepare("SELECT misc FROM attachments WHERE url = ?").get(url).misc;
            misc = JSON.stringify({ ...JSON.parse(currentMisc), ...JSON.parse(misc) });
            db.prepare("UPDATE attachments SET misc = ? WHERE url = ?").run(misc, url);
        }
    } catch (e) {
        return res.status(400).send("Something went wrong");
    }

    res.send("Attachment updated");
});

app.get("/view/:url", (req, res) => { // view attachment -- get so that it can be src in <img>s
    const url = req.params.url;
    if (!url) return res.status(400).send("Missing URL");

    const attachment = db.prepare("SELECT preview FROM attachments WHERE url = ?").get(url);
    if (attachment == undefined) return res.status(404).send('Attachment not found');

    res.type("image/svg+xml");
    res.send(attachment.preview);
});


// Proxy endpoint
app.get("/proxy-image", async (req, res) => {
    try {
        let url = req.query.url;
        if (!url) return res.status(400).send("Missing URL");
        const Url = new URL(url, `http://${req.headers.host}`);
        if (Url.host == process.env.SELF) url = "http://127.0.0.1:" + process.env.PORT + Url.pathname;

        const response = await fetch(url);
        if (!response.ok) return res.status(response.status).send("Failed to fetch image");

        const contentType = response.headers.get("content-type") || "application/octet-stream";
        res.setHeader("Content-Type", contentType);

        const buffer = await response.arrayBuffer();
        res.send(Buffer.from(buffer));
    } catch (err) {
        console.error(err);
        res.status(500).send("Error fetching image");
    }
});

