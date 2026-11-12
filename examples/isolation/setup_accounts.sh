#!/usr/bin/env bash
# Creates the two accounts and the directory layout the release service needs, with the owners and modes that matter.
# Run as root. Safe to run again: it never deletes, and it never overwrites a file that exists.
#
#   sudo ./setup_accounts.sh
#
# Variables: SERVICE_USER (default zts-release), APP_USER (default zts-app), CREATE_USERS=0 to leave the accounts alone,
# PREFIX to build the layout under another directory (used by the tests).
set -euo pipefail

SERVICE_USER=${SERVICE_USER:-zts-release}
APP_USER=${APP_USER:-zts-app}
CREATE_USERS=${CREATE_USERS:-1}
PREFIX=${PREFIX:-}

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

if [ "$CREATE_USERS" = 1 ]; then
  for account in "$SERVICE_USER" "$APP_USER"; do
    id -u "$account" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$account"
  done
fi
if [ "$SERVICE_USER" = "$APP_USER" ]; then
  echo "the service and the application must be different accounts" >&2
  exit 1
fi

# Configuration anyone may read but only root may change: the trust root lives here. The service is NOT its owner,
# so a compromised service cannot rewrite who it trusts.
install -d -o root -g root -m 0755 "$PREFIX/etc/zts"

# Secrets: owned by the service, invisible to everyone else (the directory is 700, so the application cannot even list it).
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$PREFIX/etc/zts/secrets"

# State the service writes: the ledger, its receipts, the ledger key. Same rule.
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$PREFIX/var/lib/zts"

# The ledger key must exist before the first start (ZTS would create it, but then you would not know it was there).
key="$PREFIX/var/lib/zts/ledger.key"
if [ ! -e "$key" ]; then
  (umask 077 && head -c 32 /dev/urandom > "$key")
  chown "$SERVICE_USER:$SERVICE_USER" "$key"
  chmod 0600 "$key"
  echo "created $key"
fi

cat <<NOTE
Layout ready under ${PREFIX:-/}:

  /etc/zts/                      root:root          755   configuration
  /etc/zts/trust-root.json       root:root          644   YOU install it (see TRUST_ROOT_PROCEDURE.md)
  /etc/zts/secrets/              $SERVICE_USER      700   secrets
  /etc/zts/secrets/delivery.cred       YOU create   $SERVICE_USER 600   credentials for the receiver
  /etc/zts/secrets/replay.dsn          YOU create   $SERVICE_USER 600   replay database connection string
  /etc/zts/secrets/release-signing.key YOU create   $SERVICE_USER 600   32-byte release signature key
  /var/lib/zts/                  $SERVICE_USER      700   state
  /var/lib/zts/ledger.key        $SERVICE_USER      600   created above
  /var/lib/zts/ledger.jsonl      created by ZTS, 600
  /var/lib/zts/receipts.jsonl    created by ZTS, 600

Put each secret in place with:  install -m 600 -o $SERVICE_USER -g $SERVICE_USER FILE /etc/zts/secrets/NAME
Then, as $APP_USER, run check_isolation.py (README.md, step 3).
NOTE
