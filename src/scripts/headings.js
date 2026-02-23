const Database = require("better-sqlite3");
require('dotenv').config();

const db = new Database("../../data/bluebook.sqlite");
console.log("Connected to db: ", db);

const notes = db.prepare("SELECT id, name, content FROM notes").all();
for (let note of notes) {
    console.log(note.id, note.name);
    let content = JSON.parse(note.content);
    content = content.map(line => {
        let deco = line.decos?.filter(e => ["h1", "h2", "h3", "h4"].includes(e));
        if (deco == undefined || deco.length == 0) return line;
        if (deco.length > 0) {
            console.log(deco[0]);
            switch (deco[0]) {
                case "h1": return { ...line, decos: ["h1"] }
                case "h2": return { ...line, decos: ["subtitle"] }
                case "h3": return { ...line, decos: ["h2"] }
                case "h4": return { ...line, decos: ["h3"] }
            }
        }
    });

    let success = db.prepare("UPDATE notes SET content = ? WHERE id = ?").run(JSON.stringify(content), note.id);
    console.log(success);

    console.log(content);
} 
