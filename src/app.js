const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcrypt");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
require("dotenv").config();

const app = express();

app.use(cors({
    origin: process.env.ALLOW.split(","),
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

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));

app.use(
    session({
        store: new SQLiteStore({
            db: "sessions.sqlite",
            dir: "./data",
            ttl: 86400
            // table: "sessions",
        }),
        secret: process.env.SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: {
            maxAge: 1000 * 60 * 60 * 24,
            httpOnly: true,
        },
    })
);

const db = new sqlite3.Database("data/bluebook.sqlite", (err) => {
    if (err) {
        console.error("Failed to connect to db:", err);
        process.exit(1);
    }

    console.log("Connected to db");
});

// Promise wrappers around sqlite3
const dbGet = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
};

const dbAll = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
};

const dbRun = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) reject(err);
            else {
                resolve({
                    lastInsertRowid: this.lastID,
                    changes: this.changes
                });
            }
        });
    });
};

const generateNewUrl = async (table) => {
    const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    let url = "";
    const randomBytes = crypto.randomBytes(10);

    for (let i = 0; i < 10; i++) {
        url += abc[randomBytes[i] % abc.length];
    }

    const alreadyExists = await dbGet(
        `SELECT id FROM ${table} WHERE url = ?`,
        [url]
    );

    if (alreadyExists) return generateNewUrl(table);

    return url;
};

app.listen(3000, () => {
    console.log(`Server running on port 3000`);
});

app.get("/", (req, res) => {
    res.json({ welcomeMessage: "Hello world!" });
});

app.post("/new_user", async (req, res) => {
    const { email, name, password } = req.body;

    if (email == undefined) return res.status(400).send("Email is required");
    if (name == undefined) return res.status(400).send("Name is required");
    if (password == undefined) return res.status(400).send("Password is required");

    const hashed = await bcrypt.hash(password, 12);

    try {
        await dbRun(
            "INSERT INTO users (email, name, password) VALUES (?, ?, ?)",
            [email, name, hashed]
        );
    } catch (e) {
        if (e.code === "SQLITE_CONSTRAINT") {
            return res.status(400).send("Email already exists");
        }

        console.error(e);
        return res.status(500).send("Something went wrong");
    }

    res.status(200).send("User added");
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (email == undefined) return res.status(400).send("Email is required.");
    if (password == undefined) return res.status(400).send("Password is required.");

    const user = await dbGet(
        "SELECT id, password FROM users WHERE email = ?",
        [email]
    );

    if (!user) return res.status(401).send("User not found");

    if (!await bcrypt.compare(password, user.password)) {
        return res.status(401).send("Wrong password");
    }

    req.session.userId = user.id;
    res.send("Logged in");
});

app.get("/user", async (req, res) => {
    if (!req.session.userId) return res.status(401).send("Not logged in");

    const user = await dbGet(
        "SELECT id, email, name, misc FROM users WHERE id = ?",
        [req.session.userId]
    );

    res.json(user);
});

app.get("/notes", async (req, res) => {
    if (!req.session.userId) return res.status(401).send("Not logged in");

    const notes = await dbAll(
        "SELECT id, url, name, user_id, misc FROM notes WHERE user_id = ?",
        [req.session.userId]
    );

    res.json(notes);
});

app.post("/note", async (req, res) => {
    if (!req.session.userId) return res.status(401).send("Not logged in");

    const { id } = req.body;
    if (id == undefined) return res.status(400).send("Id is required.");

    const note = await dbGet(
        "SELECT * FROM notes WHERE id = ?",
        [id]
    );

    if (note == undefined) return res.status(400).send("Note doesn't exist");

    if (note.user_id !== req.session.userId) {
        return res.status(403).send("Not your note");
    }

    res.json(note);
});

app.post("/note_by_url", async (req, res) => {
    const { url } = req.body;

    if (url == undefined) return res.status(400).send("Url is required");

    const note = await dbGet(
        "SELECT * FROM notes WHERE url = ?",
        [url]
    );

    if (note == undefined) return res.status(400).send("Note not found");

    res.json(note);
});

app.post("/new_note", async (req, res) => {
    if (!req.session.userId) return res.status(401).send("Not logged in");

    const { name } = req.body;

    if (name == undefined) return res.status(400).send("Name is required");
    if (name.endsWith("/")) return res.status(400).send('Name can not end in "/"');

    const url = await generateNewUrl("notes");

    const note = await dbRun(
        "INSERT INTO notes (name, url, user_id, content, misc) VALUES (?, ?, ?, ?, ?)",
        [
            name,
            url,
            req.session.userId,
            JSON.stringify([]),
            JSON.stringify({ created: Date.now() })
        ]
    );

    res.json({ id: note.lastInsertRowid });
});

app.post("/update_note", async (req, res) => {
    if (!req.session.userId) return res.status(401).send("Not logged in");

    let { content, name, misc, id } = req.body;

    if (id == undefined) return res.status(400).send("Id is required.");

    const note = await dbGet(
        "SELECT user_id FROM notes WHERE id = ?",
        [id]
    );

    if (note == undefined) return res.status(400).send("Note doesn't exist");

    if (note.user_id !== req.session.userId) {
        return res.status(403).send("Not your note");
    }

    try {
        if (content) {
            await dbRun(
                "UPDATE notes SET content = ? WHERE id = ?",
                [content, id]
            );
        }

        if (name) {
            await dbRun(
                "UPDATE notes SET name = ? WHERE id = ?",
                [name, id]
            );
        }

        if (misc) {
            const currentMisc = await dbGet(
                "SELECT misc FROM notes WHERE id = ?",
                [id]
            );

            misc = JSON.stringify({
                ...JSON.parse(currentMisc.misc),
                ...JSON.parse(misc)
            });

            await dbRun(
                "UPDATE notes SET misc = ? WHERE id = ?",
                [misc, id]
            );
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

app.get("/attachments", async (req, res) => {
    if (!req.session.userId) return res.status(401).send("Not logged in");

    const attachments = await dbAll(
        "SELECT id, url, user_id, type, misc FROM attachments WHERE user_id = ?",
        [req.session.userId]
    );

    res.json(attachments);
});

app.post("/attachment/meta", async (req, res) => {
    const { url } = req.body;

    if (url == undefined) return res.status(400).send("Url is required");

    const attachment = await dbGet(
        "SELECT id, url, user_id, type, created, misc FROM attachments WHERE url = ?",
        [url]
    );

    if (attachment == undefined) {
        return res.status(400).send("Attachment not found");
    }

    res.json(attachment);
});

app.post("/attachment/content", async (req, res) => {
    const { url } = req.body;

    if (url == undefined) return res.status(400).send("Url is required");

    const attachment = await dbGet(
        "SELECT id, url, user_id, type, created, misc, content FROM attachments WHERE url = ?",
        [url]
    );

    if (attachment == undefined) {
        return res.status(404).send("Attachment not found");
    }

    console.log({ attachment });
    res.json(attachment);
});

app.post("/attachment/all", async (req, res) => {
    const { url } = req.body;

    if (url == undefined) return res.status(400).send("Url is required");

    const attachment = await dbGet(
        "SELECT * FROM attachments WHERE url = ?",
        [url]
    );

    if (attachment == undefined) {
        return res.status(400).send("Attachment not found");
    }

    res.json(attachment);
});

app.post("/new_attachment", async (req, res) => {
    if (!req.session.userId) return res.status(401).send("Not logged in");

    const { type } = req.body;

    if (type == undefined) return res.status(400).send("Type is required.");

    if (!["graph", "geometry", "sketch"].includes(type)) {
        return res.status(400).send(
            "Type needs to be graph, geometry or sketch."
        );
    }

    const url = await generateNewUrl("attachments");

    await dbRun(
        "INSERT INTO attachments (url, user_id, type, preview, content) VALUES (?, ?, ?, ?, ?)",
        [
            url,
            req.session.userId,
            type,
            "",
            JSON.stringify([])
        ]
    );

    res.json({ url });
});

app.post("/update_attachment", async (req, res) => {
    if (!req.session.userId) return res.status(401).send("Not logged in");

    let { content, preview, misc, url } = req.body;

    if (url == undefined) return res.status(400).send("Url is required.");

    const attachment = await dbGet(
        "SELECT user_id FROM attachments WHERE url = ?",
        [url]
    );

    if (attachment == undefined) {
        return res.status(400).send("Attachment doesn't exist");
    }

    if (attachment.user_id !== req.session.userId) {
        return res.status(403).send("Not your attachment");
    }

    try {
        if (content) {
            await dbRun(
                "UPDATE attachments SET content = ? WHERE url = ?",
                [content, url]
            );
        }

        if (preview) {
            await dbRun(
                "UPDATE attachments SET preview = ? WHERE url = ?",
                [preview, url]
            );
        }

        if (misc) {
            const currentMisc = await dbGet(
                "SELECT misc FROM attachments WHERE url = ?",
                [url]
            );

            misc = JSON.stringify({
                ...JSON.parse(currentMisc.misc),
                ...JSON.parse(misc)
            });

            await dbRun(
                "UPDATE attachments SET misc = ? WHERE url = ?",
                [misc, url]
            );
        }
    } catch (e) {
        return res.status(400).send("Something went wrong");
    }

    res.send("Attachment updated");
});

app.get("/view/:url", async (req, res) => {
    const url = req.params.url;

    if (!url) return res.status(400).send("Missing URL");

    const attachment = await dbGet(
        "SELECT preview FROM attachments WHERE url = ?",
        [url]
    );

    if (attachment == undefined) {
        return res.status(404).send("Attachment not found");
    }

    res.type("image/svg+xml");
    res.send(attachment.preview);
});

// Proxy endpoint
app.get("/proxy-image", async (req, res) => {
    try {
        let url = req.query.url;

        if (!url) return res.status(400).send("Missing URL");

        const Url = new URL(url, `http://${req.headers.host}`);

        if (Url.host == process.env.SELF) {
            url = "http://127.0.0.1:3000" + Url.pathname;
        }

        const response = await fetch(url);

        if (!response.ok) {
            return res.status(response.status).send("Failed to fetch image");
        }

        const contentType =
            response.headers.get("content-type") ||
            "application/octet-stream";

        res.setHeader("Content-Type", contentType);

        const buffer = await response.arrayBuffer();
        res.send(Buffer.from(buffer));
    } catch (err) {
        console.error(err);
        res.status(500).send("Error fetching image");
    }
});
