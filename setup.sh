#!/usr/bin/env bash
# authz.lock prototype — one-time setup on Linux / WSL2 (Ubuntu). Needs: git, python3, docker (or a local Postgres 16).
set -euo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)
TEMPLATE_SHA=cb740b656d7a0a6c5e12c7bf8e50343ec94ee9c7   # fastapi/full-stack-fastapi-template commit the demo was built on

command -v uv >/dev/null || { curl -LsSf https://astral.sh/uv/install.sh | sh; export PATH="$HOME/.local/bin:$PATH"; }

# 1. Postgres 16 with trust auth on localhost:5432 (skip if you already run one)
if ! pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
  docker run -d --name authz-pg -e POSTGRES_HOST_AUTH_METHOD=trust -p 5432:5432 postgres:16 -c autovacuum=off
  until pg_isready -h localhost -p 5432 >/dev/null 2>&1; do sleep 1; done
fi

# 2. target app pinned to the demo commit, plus the 6 scenario PR branches
if [ ! -d target ]; then
  git init -q target && git -C target remote add origin https://github.com/fastapi/full-stack-fastapi-template.git
  git -C target fetch -q --depth 1 origin "$TEMPLATE_SHA" && git -C target checkout -q FETCH_HEAD
fi
cd target
git config user.email authzlock@example.com && git config user.name authzlock
git checkout -q -B base
mkdir -p backend/app/frontend && echo '<html>stub</html>' > backend/app/frontend/index.html
git add -f backend/app/frontend/index.html && git commit -qm "base: frontend stub so the backend boots standalone" || true
for p in "$HERE"/scenarios/*.patch; do
  b=$(basename "$p" .patch); git checkout -q -B "$b" base && git am -q "$p"
done
git checkout -q base

# 3. Python 3.14 env for the target app (+ SMTP sink used by the probe)
uv python install 3.14
uv sync --python 3.14 -q
uv pip install --python .venv -q aiosmtpd
cd "$HERE"

# 4. production-profile env (FASTAPI_ENV unset, fresh random secrets) and the template's dev profile
gen() { python3 -c 'import secrets;print(secrets.token_hex(16))'; }
cat > target.env <<ENV
PROJECT_NAME="Full Stack FastAPI Project"
SECRET_KEY=$(gen)
FIRST_SUPERUSER=admin@example.com
FIRST_SUPERUSER_PASSWORD=$(gen)
SMTP_HOST=127.0.0.1
EMAILS_FROM_EMAIL=info@example.com
SMTP_TLS=False
SMTP_PORT=1025
DATABASE_URL=postgresql://postgres:pw$(gen)@localhost:5432/app
ENV
{ cat target.env; echo "FASTAPI_ENV=development"; } > dev.env
echo "Setup done. Run:  python3 run_scenarios.py target   (≈15 min)  then  python3 regress_tests.py target results target.env"
