#!/usr/bin/env bash
set -euo pipefail

git config user.name "RustClash Labs"
git config user.email "rustclash.labs@proton.me"
git config core.hooksPath .githooks

echo "Configured Git identity: $(git config user.name) <$(git config user.email)> (hooksPath=.githooks)"
