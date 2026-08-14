# Docker command to nudge this badboy on my machine:

pbpaste | docker run --rm --platform linux/amd64 -i \
    -v "$PWD:/data" \
    bluebook_pandoc \
    - \
    --include-in-header=/data/preamble.tex \
    --pdf-engine=xelatex \
    --pdf-engine-opt=--shell-escape \
    -o /data/output.pdf
