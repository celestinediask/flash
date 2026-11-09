#!/usr/bin/env bash
# Ask for a password and print the UI_PASSWORD_HASH line for your .env file.
# Needs only openssl (3.0+). Produces a PBKDF2-SHA256 hash the app accepts.
set -euo pipefail

read -r -s -p "Password: " pw; echo
[ -n "$pw" ] || { echo "Password cannot be empty." >&2; exit 1; }
read -r -s -p "Repeat password: " pw2; echo
[ "$pw" = "$pw2" ] || { echo "Passwords do not match." >&2; exit 1; }

iter=600000
salt=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 16 || true)
hex=$(openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt "pass:$pw" \
      -kdfopt "salt:$salt" -kdfopt "iter:$iter" PBKDF2 | tr -d ':' | tr 'A-F' 'a-f')


printf 'pbkdf2:sha256:%s$%s$%s\n' "$iter" "$salt" "$hex"
