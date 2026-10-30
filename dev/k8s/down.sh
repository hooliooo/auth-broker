#!/usr/bin/env bash
# Deletes the local cluster and everything in it, its database included.
set -euo pipefail
kind delete cluster --name auth-broker
