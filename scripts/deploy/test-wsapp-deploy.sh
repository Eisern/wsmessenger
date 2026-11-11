#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of WS Messenger. See LICENSE for terms.
#
# Tests for wsapp-deploy, run by CI (test-deploy in .github/workflows/ci.yml):
#
#   docker run --rm -v "$PWD/scripts/deploy:/src:ro" buildpack-deps:noble-scm \
#       sh /src/test-wsapp-deploy.sh
#
# A throwaway origin, a deployment checkout owned by wsapp, and the script run
# as root against them - real git, runuser, flock and sh. systemctl, curl,
# journalctl, sleep and pip are stubs that record what was asked of them.
# Each protection in wsapp-deploy was checked to fail one of these when removed.
set -u
export DEBIAN_FRONTEND=noninteractive
command -v git >/dev/null || { apt-get update -qq >/dev/null && apt-get install -y -qq git >/dev/null; } || { echo "apt failed"; exit 2; }

useradd -m wsapp
git config --global user.email t@t; git config --global user.name t
git config --global init.defaultBranch main

mkdir -p /stubs
cat > /stubs/systemctl <<'EOF'
#!/bin/sh
echo "systemctl $*" >> /tmp/calls
case "$1" in
  cat) [ -f /tmp/has_backup ] ;;
  start) [ ! -f /tmp/backup_fails ] ;;
  restart) [ ! -f /tmp/restart_fails ] ;;
  *) exit 0 ;;
esac
EOF
cat > /stubs/curl <<'EOF'
#!/bin/sh
echo "curl" >> /tmp/curls
[ -f /tmp/all_down ] && exit 7
head=$(git -c safe.directory='*' -C /home/wsapp/wsmessenger rev-parse HEAD)
[ "$head" != "$(cat /tmp/bad 2>/dev/null)" ] || exit 7
exit 0
EOF
cat > /stubs/journalctl <<'EOF'
#!/bin/sh
echo "JOURNAL-STUB secret-looking line"
EOF
cat > /stubs/sleep <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x /stubs/*
export PATH=/stubs:$PATH

install -m 755 /src/wsapp-deploy /usr/local/sbin/wsapp-deploy

# origin and a working clone to make commits in
git init -q --bare /srv/origin.git
git clone -q /srv/origin.git /work 2>/dev/null
cd /work
mkdir -p server
echo v1 > server/main.py; echo "fastapi" > server/requirements.txt; echo s1 > server/schema.sql; echo d1 > README
git add -A; git commit -qm C1; C1=$(git rev-parse HEAD)
echo d2 > README; git commit -qam C2; C2=$(git rev-parse HEAD)
echo v3 > server/main.py; git commit -qam C3; C3=$(git rev-parse HEAD)
echo "fastapi
uvicorn" > server/requirements.txt; git commit -qam C4; C4=$(git rev-parse HEAD)
echo s5 > server/schema.sql; echo v5 > server/main.py; git commit -qam C5; C5=$(git rev-parse HEAD)
git push -q origin main
git checkout -qb other; echo x > server/main.py; git commit -qam OTHER; OTHER=$(git rev-parse HEAD); git push -q origin other
git checkout -q main
chown -R wsapp:wsapp /srv/origin.git

pass=0; fail=0
ok() { pass=$((pass+1)); echo "  ok   $1"; }
bad() { fail=$((fail+1)); echo "  FAIL $1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# A fresh deployment checkout at commit $1, with a pip stub in .venv
reset_at() {
  rm -rf /home/wsapp/wsmessenger /tmp/calls /tmp/curls /tmp/pip /tmp/bad /tmp/all_down /tmp/backup_fails /tmp/pip_fails /tmp/restart_fails /var/log/wsapp-deploy.log
  touch /tmp/calls /tmp/curls /tmp/pip /tmp/has_backup
  runuser -u wsapp -- git clone -q /srv/origin.git /home/wsapp/wsmessenger
  runuser -u wsapp -- git -C /home/wsapp/wsmessenger reset -q --hard "$1"
  mkdir -p /home/wsapp/wsmessenger/.venv/bin
  printf '#!/bin/sh\necho "pip $*" >> /tmp/pip\n[ ! -f /tmp/pip_fails ]\n' > /home/wsapp/wsmessenger/.venv/bin/pip
  chmod +x /home/wsapp/wsmessenger/.venv/bin/pip
  chmod 666 /tmp/pip /tmp/calls /tmp/curls
  echo untracked > /home/wsapp/wsmessenger/.schema-applied
  chown -R wsapp:wsapp /home/wsapp/wsmessenger
}
run() { OUT=$(/usr/local/sbin/wsapp-deploy "$@"); RC=$?; }
head_is() { [ "$(git -c safe.directory='*' -C /home/wsapp/wsmessenger rev-parse HEAD)" = "$1" ]; }
restarts() { grep -c "^systemctl restart wsapp" /tmp/calls; }

echo "bad arguments"
reset_at "$C1"
run ""; check "empty refused" '[ $RC -ne 0 ] && echo "$OUT" | grep -q "expected a full commit id"'
run "xyz"; check "non-hex refused" '[ $RC -ne 0 ]'
run "$(echo "$C2" | cut -c1-12)"; check "short id refused" '[ $RC -ne 0 ]'
run "$C2; touch /tmp/pwned"; check "shell junk refused, nothing run" '[ $RC -ne 0 ] && [ ! -f /tmp/pwned ]'
check "no restart from refusals" '[ "$(restarts)" = 0 ] && head_is "$C1"'

echo "only commits on origin/main"
reset_at "$C1"
run "$OTHER"; check "branch commit refused" '[ $RC -ne 0 ] && echo "$OUT" | grep -q "not on origin/main" && head_is "$C1"'
run "0123456789012345678901234567890123456789"; check "unknown commit refused" '[ $RC -ne 0 ] && head_is "$C1"'

echo "no-ops"
reset_at "$C3"
run "$C3"; check "already there" '[ $RC -eq 0 ] && echo "$OUT" | grep -q "already running" && [ "$(restarts)" = 0 ]'
run "$C2"; check "never goes back" '[ $RC -eq 0 ] && echo "$OUT" | grep -q "not going back" && head_is "$C3" && [ "$(restarts)" = 0 ]'

echo "forward, nothing under server/"
reset_at "$C1"
run "$C2"; check "moves, no backup, no restart" '[ $RC -eq 0 ] && head_is "$C2" && [ "$(restarts)" = 0 ] && ! grep -q "start wsapp-backup" /tmp/calls'

echo "forward, server/ changed"
reset_at "$C2"
run "$C3"; check "backup then restart, healthy" '[ $RC -eq 0 ] && head_is "$C3" && [ "$(restarts)" = 1 ] && [ "$(grep -n "" /tmp/calls | grep "start wsapp-backup" | cut -d: -f1)" -lt "$(grep -n "" /tmp/calls | grep "restart wsapp" | cut -d: -f1)" ]'
check "no pip when requirements did not change" '[ ! -s /tmp/pip ]'
check "untracked .schema-applied kept" '[ -f /home/wsapp/wsmessenger/.schema-applied ]'

echo "requirements changed"
reset_at "$C3"
run "$C4"; check "pip ran, deployed" '[ $RC -eq 0 ] && head_is "$C4" && grep -q "install" /tmp/pip'
reset_at "$C3"; touch /tmp/pip_fails
run "$C4"; check "pip failure: back on old, no restart" '[ $RC -ne 0 ] && head_is "$C3" && [ "$(restarts)" = 0 ] && echo "$OUT" | grep -q "dependencies failed"'

echo "backup"
reset_at "$C2"; touch /tmp/backup_fails
run "$C3"; check "backup failure: nothing deployed" '[ $RC -ne 0 ] && head_is "$C2" && [ "$(restarts)" = 0 ]'
reset_at "$C2"; rm -f /tmp/has_backup
run "$C3"; check "no backup unit: deploys anyway" '[ $RC -eq 0 ] && head_is "$C3" && ! grep -q "start wsapp-backup" /tmp/calls'

echo "new version does not come up"
reset_at "$C4"; echo "$C5" > /tmp/bad
run "$C5"; check "rolled back, fails" '[ $RC -ne 0 ] && head_is "$C4" && [ "$(restarts)" = 2 ] && echo "$OUT" | grep -q "rolled back"'
check "schema change warned" 'echo "$OUT" | grep -q "schema.sql changed"'
check "journal kept out of the caller output" '! echo "$OUT" | grep -q JOURNAL-STUB && grep -q JOURNAL-STUB /var/log/wsapp-deploy.log'
reset_at "$C2"; echo "$C3" > /tmp/bad; touch /tmp/restart_fails
run "$C3"; check "restart itself fails: still rolled back" '[ $RC -ne 0 ] && head_is "$C2" && echo "$OUT" | grep -q "rolled back"'
rm -f /tmp/restart_fails
reset_at "$C4"; touch /tmp/all_down
run "$C5"; check "rollback down too: says DOWN" '[ $RC -ne 0 ] && echo "$OUT" | grep -q "is DOWN"'

echo "local changes"
reset_at "$C2"; echo dirty >> /home/wsapp/wsmessenger/README
run "$C3"; check "refused, untouched" '[ $RC -ne 0 ] && echo "$OUT" | grep -q "local changes" && grep -q dirty /home/wsapp/wsmessenger/README'

echo "detached HEAD"
reset_at "$C2"; runuser -u wsapp -- git -C /home/wsapp/wsmessenger checkout -q --detach
run "$C3"; check "refused" '[ $RC -ne 0 ] && echo "$OUT" | grep -q "not on branch"'

echo "one at a time"
reset_at "$C2"
( flock 9; /bin/sleep 3 ) 9>/run/wsapp-deploy.lock &
/bin/sleep 0.3
t0=$(date +%s%3N); run "$C3"; t1=$(date +%s%3N)
check "waited for the lock" '[ $RC -eq 0 ] && [ $((t1 - t0)) -ge 2000 ]'
wait

echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
