#!/bin/sh
set -eu

keychain_service='com.putereamintii.postiz.local'
keychain_account="$(id -un)"

POSTIZ_JWT_SECRET="$(security find-generic-password \
  -s "$keychain_service" \
  -a "$keychain_account" \
  -w)"
export POSTIZ_JWT_SECRET

docker compose up -d
docker compose ps
