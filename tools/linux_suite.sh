#!/bin/sh
# Run the full test suite on Linux in throwaway Docker containers, the way CI (tests.yml) does,
# without pushing anything. Needs Docker. The repo is mounted read-only; nothing is written back.
#
#   sh tools/linux_suite.sh            # Python 3.8 and 3.13 (oldest and newest supported)
#   sh tools/linux_suite.sh 3.12       # one or more chosen versions
#
# On Windows (Git Bash), run it with MSYS_NO_PATHCONV=1 so the container paths are not rewritten.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSIONS=${*:-"3.8 3.13"}
INNER=$(mktemp)
cat > "$INNER" <<'EOF'
set -e
mkdir -p /work && cd /src
tar --exclude=./.git --exclude=./release --exclude=./build/.venv --exclude='*/__pycache__' -cf - . | tar -xf - -C /work
cd /work
P="python -m pip install -q --root-user-action=ignore --disable-pip-version-check --require-hashes -r"
if python -c "import sys; sys.exit(sys.version_info < (3, 10))"; then $P build/requirements-test.txt
else $P build/requirements-test-legacy.txt; fi
if python -c "import sys; sys.exit(sys.version_info < (3, 9))"; then $P requirements-backups.txt; fi
mkdir -p dist && python build/bundle.py > /dev/null
set +e
python -m pytest scan -q -rf -p no:cacheprovider > /tmp/pytest.txt 2>&1
code=$?
grep -E "^(FAILED|ERROR) " /tmp/pytest.txt
tail -1 /tmp/pytest.txt
exit $code
EOF
status=0
for v in $VERSIONS; do
  echo "##### Linux, Python $v"
  docker run --rm -v "$ROOT:/src:ro" -v "$INNER:/run.sh:ro" "python:$v-slim" sh /run.sh || status=1
done
rm -f "$INNER"
exit $status
