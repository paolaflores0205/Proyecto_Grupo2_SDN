#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
install -d -m 0755 /opt/sdn-r4 /etc/sdn-r4
install -d -o ubuntu -g ubuntu -m 0750 /var/lib/sdn-r4
install -m 0755 "$SRC_DIR/sdn_r4.py" /opt/sdn-r4/sdn_r4.py
install -m 0644 "$SRC_DIR/config.json" /etc/sdn-r4/config.json
install -m 0644 "$SRC_DIR/sdn-r4.service" /etc/systemd/system/sdn-r4.service

systemctl daemon-reload
systemctl enable --now sdn-r4.service
systemctl --no-pager status sdn-r4.service
