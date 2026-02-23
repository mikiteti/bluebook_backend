-- =========================
-- ATTACHMENTS TABLE
-- =========================

CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    preview TEXT,
    content TEXT,
    user_id INTEGER,
    created INTEGER NOT NULL DEFAULT (unixepoch()),
    misc TEXT
);
