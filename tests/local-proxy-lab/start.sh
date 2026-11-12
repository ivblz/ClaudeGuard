#!/bin/bash
set -euo pipefail
sudo /bin/launchctl bootstrap system /tmp/claudeguard-proxy-lab/service.plist
