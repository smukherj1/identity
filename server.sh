#!/usr/bin/bash
set -eu

ID="$(hostname)"

go run bin/identity/main.go --priv data/ec-sign-p256-priv.pem --pub data/ec-sign-p256-pub.pem --id "${ID}"