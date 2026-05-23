#!/usr/bin/env sh
set -eu

go run ./cmd/sast-agent -path ./examples/vulnerable
