#!/bin/bash
# EC2 user-data for an autoscaling group: runs as root at first boot. The image already has the PeopleSoft (or
# other) services as user units of PSUSER. One instance was set up by hand first, with
#   eaveswatch URL MODEL --system ps-hr-app
# and its loop keeps the system's profile current in the bucket.
set -euo pipefail
PSUSER=psadm2
SYSTEM=ps-hr-app
STORE=s3://my-eaves-bucket/eaveswatch
# The reviewer's model key: from your secret store, into the environment only (the instance role reads it)
KEY=$(aws secretsmanager get-secret-value --secret-id eaveswatch/model-key --query SecretString --output text)

loginctl enable-linger "$PSUSER"                     # user units run with nobody logged in
uid=$(id -u "$PSUSER")
until [ -S "/run/user/$uid/bus" ]; do sleep 1; done  # the user's systemd is up
sudo -u "$PSUSER" -i env XDG_RUNTIME_DIR="/run/user/$uid" EAVESWATCH_MODEL_KEY="$KEY" \
  bash -lc "pipx install hobkin-eaveswatch && eaveswatch restore $STORE $SYSTEM"
