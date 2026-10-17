#!/bin/bash
# Run the interop suite against the docker ARC CE + SLURM cluster in ARC-test/cluster.
#
#   tools/interop-docker.sh [/path/to/ARC-test/cluster] [pytest args...]
#
# The CE's host certificate names arc-ce.arctest.local, which only resolves
# inside the compose network, so the client runs in a throwaway python
# container on that network: a clean Linux install of xrdclient, xgfalclient
# and xrdarc from this checkout's siblings. The test CA and the 'tester' user
# certificate are copied out of the CE; the proxy is made by `xrdarc proxy`.
set -euo pipefail
CLUSTER=${1:-$(cd "$(dirname "$0")/../../../ARC-test/cluster" && pwd)}
shift || true
GFAL=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
NAME=xrdarc-interop-$$
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

cd "$CLUSTER"
docker compose --profile arc up -d >/dev/null
CE=$(docker compose ps -q arc-ce)
until docker exec "$CE" test -f /etc/grid-security/.e2e-ca; do sleep 2; done

mkdir -p "$WORK/certificates" "$WORK/globus"
for f in $(docker exec "$CE" sh -c 'cd /etc/grid-security/certificates && ls *.0 *.signing_policy'); do
  docker exec "$CE" cat "/etc/grid-security/certificates/$f" > "$WORK/certificates/$f"
done
docker exec "$CE" cat /home/tester/.globus/usercert.pem > "$WORK/globus/usercert.pem"
docker exec "$CE" cat /home/tester/.globus/userkey.pem > "$WORK/globus/userkey.pem"
chmod 600 "$WORK/globus/userkey.pem"

NETWORK=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$CE")
docker run -d --name "$NAME" --network "$NETWORK" -v "$GFAL:/gfal:ro" -v "$WORK:/creds:ro" \
  python:3.12-slim sleep infinity >/dev/null
docker exec "$NAME" bash -c '
  set -e
  apt-get -qq update >/dev/null && apt-get -qq install -y openssl >/dev/null
  for p in xrdclient xgfalclient xrdarc; do cp -r /gfal/$p /tmp/$p; rm -rf /tmp/$p/.venv; done
  pip install -q --root-user-action=ignore /tmp/xrdclient /tmp/xgfalclient /tmp/xrdarc pytest
  X509_USER_CERT=/creds/globus/usercert.pem X509_USER_KEY=/creds/globus/userkey.pem \
    X509_CERT_DIR=/creds/certificates xrdarc proxy >/dev/null'
docker exec -e X509_CERT_DIR=/creds/certificates -e XRDARC_INTEROP=1 \
  -e XRDARC_INTEROP_CE=arc-ce.arctest.local -e XRDARC_INTEROP_RTE=ENV/PROXY \
  -e XRDARC_INTEROP_TIMEOUT=600 "$NAME" \
  bash -c "cd /tmp/xrdarc && python -m pytest tests/test_interop.py -v -p no:cacheprovider -o addopts= $*"
