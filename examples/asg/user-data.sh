#!/bin/bash
# EC2 user-data: every instance of the system runs this at boot, the first one included (it creates the system;
# the rest join it). Runs as root; the image already has the services as user units of PSUSER, and Python 3.9+.
# Feed the flags from your own variables or secret store: eaveswatch takes them as given.
set -euo pipefail
PSUSER=psadm2
MODEL_KEY=$(aws secretsmanager get-secret-value --secret-id my/model-key --query SecretString --output text)

loginctl enable-linger "$PSUSER"                     # user units run with nobody logged in
uid=$(id -u "$PSUSER")
until [ -S "/run/user/$uid/bus" ]; do sleep 1; done  # the user's systemd is up
sudo -u "$PSUSER" -i env XDG_RUNTIME_DIR="/run/user/$uid" MODEL_KEY="$MODEL_KEY" bash -lc '
  pipx install "eaveswatch[hobkin]"
  eaveswatch boot --store s3://my-eaves-bucket/eaveswatch --system ps-hr-app \
    --model-url https://api.example.gov/v1 --model my-model --model-key "$MODEL_KEY" \
    --alert-email ops@example.gov --publish-dir /var/www/html/eaveswatch'
