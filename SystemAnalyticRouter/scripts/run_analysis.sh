#!/usr/bin/env bash
set -euo pipefail

source .venv/bin/activate
sarouter --settings configs/settings.yml monitor --duration 60 --connections
