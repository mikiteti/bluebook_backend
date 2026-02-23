RUN .sql:
docker run --rm -it \
  -v <VOLUME>:/data \
  nouchka/sqlite3 \
  sqlite3 /data/bluebook.sqlite < script.sql
