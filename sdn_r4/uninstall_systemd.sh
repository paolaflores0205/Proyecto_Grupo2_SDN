#!/usr/bin/env bash
set -euo pipefail

systemctl disable --now sdn-r4.service 2>/dev/null || true
if [ -x /opt/sdn-r4/sdn_r4.py ]; then
  /usr/bin/python3 /opt/sdn-r4/sdn_r4.py --config /etc/sdn-r4/config.json cleanup || true
fi
rm -f /etc/systemd/system/sdn-r4.service
systemctl daemon-reload
echo "sdn-r4 removed cleanly."
