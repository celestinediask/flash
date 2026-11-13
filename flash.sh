#!/usr/bin/env bash
# Start/stop the flash app (UI + postback receiver) together.
# Usage: ./flash.sh start|stop|restart|status
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if   [ -x "$DIR/venv/bin/python" ];  then PY="$DIR/venv/bin/python"
elif [ -x "$DIR/.venv/bin/python" ]; then PY="$DIR/.venv/bin/python"
else PY="$(command -v python3)"; fi
APPS=(ui_server postback_server)

running() { pgrep -f "$PY ${1}.py" >/dev/null; }

start() {
  cd "$DIR" || exit 1
  for a in "${APPS[@]}"; do
    if running "$a"; then echo "$a already running"; continue; fi
    nohup "$PY" "$a.py" >"$DIR/${a%_server}.log" 2>&1 </dev/null &
    disown
    echo "started $a"
  done
}

stop() {
  for a in "${APPS[@]}"; do
    if running "$a"; then pkill -f "$PY $a.py" && echo "stopped $a"; else echo "$a not running"; fi
  done
}

status() {
  for a in "${APPS[@]}"; do
    if running "$a"; then echo "$a: running (pid $(pgrep -f "$PY $a.py" | tr '\n' ' '))"; else echo "$a: stopped"; fi
  done
}

case "$1" in
  start) start ;;
  stop) stop ;;
  restart) stop; sleep 1; start ;;
  status) status ;;
  *) echo "Usage: $0 start|stop|restart|status"; exit 1 ;;
esac
