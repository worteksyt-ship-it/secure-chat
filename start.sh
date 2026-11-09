#!/usr/bin/env bash
# Запуск чата в фоне: PORT=8080 ./start.sh
cd "$(dirname "$0")"
PORT=${PORT:-8080} setsid nohup node server.js > server.log 2>&1 < /dev/null &
echo "server pid $!"
