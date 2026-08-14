const http = require("node:http");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");

const PORT = 3000;

function runPandoc(workDir) {
    return new Promise((resolve, reject) => {
        const pandoc = spawn("pandoc", [
            "input.md",
            "--include-in-header=/app/src/preamble.tex",
            "--pdf-engine=xelatex",
            "--pdf-engine-opt=--shell-escape",
            "-o", "output.pdf"
        ], {
            cwd: workDir
        });

        let stderr = "";

        pandoc.stderr.on("data", data => {
            stderr += data.toString();
        });

        pandoc.on("error", reject);

        pandoc.on("close", code => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(stderr));
            }
        });
    });
}

const server = http.createServer(async (req, res) => {
    if (req.method !== "POST" || req.url !== "/compile") {
        res.writeHead(404);
        res.end("Not found");
        return;
    }

    try {
        const chunks = [];

        for await (const chunk of req) {
            chunks.push(chunk);
        }

        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        const markdown = body.markdown;

        if (typeof markdown !== "string") {
            throw new Error("Missing or invalid 'markdown' field");
        }

        const id = crypto.randomUUID();
        const workDir = path.join(os.tmpdir(), id);

        await fs.mkdir(workDir);

        try {
            await fs.writeFile(
                path.join(workDir, "input.md"),
                markdown
            );

            await runPandoc(workDir);

            const pdf = await fs.readFile(
                path.join(workDir, "output.pdf")
            );

            res.writeHead(200, {
                "Content-Type": "application/pdf",
                "Content-Length": pdf.length
            });

            res.end(pdf);
        } finally {
            // await fs.rm(workDir, {
            //     recursive: true,
            //     force: true
            // });
        }
    } catch (error) {
        console.error(error);

        res.writeHead(500, {
            "Content-Type": "text/plain"
        });

        res.end(error.message);
    }
});

server.listen(PORT, "0.0.0.0", () => {
    console.log(`Compiler listening on ${PORT}`);
});
