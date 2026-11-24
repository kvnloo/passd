#!/bin/sh
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
python=${PASSD_PYTHON:-python3}
if [ -x "$here/../bin/python" ] && [ -z "${PASSD_PYTHON:-}" ]; then
    python="$here/../bin/python"
fi
PYTHONPATH="$here/..${PYTHONPATH:+:$PYTHONPATH}" exec "$python" "$here/e2e_readiness.py" "$@"
