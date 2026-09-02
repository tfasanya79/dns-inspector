#!/bin/bash
set -e
cd ~/dns-inspector
git pull --ff-only
npm install --omit=dev
sudo systemctl restart dns-inspector
echo "Deployed. Service status:"
systemctl is-active dns-inspector