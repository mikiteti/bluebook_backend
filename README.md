Access db from temporary container:
docker run --rm -it \
  --user root \
  -v bluebook_backend_data:/data \
  keinos/sqlite3 \
  sqlite3 /data/bluebook.sqlite
