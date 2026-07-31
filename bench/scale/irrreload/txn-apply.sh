#!/usr/bin/env bash
# One gRPC transactional reload: plan the candidate, then apply it with the
# plan's runtime snapshot token. Used as the reloadstall harness's
# `reload_cmd` for the rustbgpd-txn cell — the harness copies the next
# generation over the candidate path first, then invokes this; a nonzero
# exit fails the reload like a failed SIGHUP.
#
# Usage: txn-apply.sh <rbgp-binary> <grpc-addr> <candidate-toml>
set -u

if [ $# -ne 3 ]; then
    echo "usage: txn-apply.sh <rbgp-binary> <grpc-addr> <candidate-toml>" >&2
    exit 2
fi
rbgp=$1
addr=$2
candidate=$3

plan_json=$("$rbgp" --addr "$addr" --json config plan "$candidate")
rc=$?
if [ "$rc" -eq 0 ]; then
    # Plan exit 0 = noop candidate: a reload that changes nothing is a
    # scenario bug, not a measurable reload.
    echo "txn-apply: candidate is a noop (plan exit 0)" >&2
    exit 1
fi
if [ "$rc" -ne 2 ]; then
    echo "txn-apply: config plan failed (exit $rc)" >&2
    exit 1
fi
token=$(printf '%s' "$plan_json" | jq -r '.runtime_snapshot_token // empty')
if [ -z "$token" ]; then
    echo "txn-apply: plan returned no runtime_snapshot_token" >&2
    exit 1
fi
if [[ ! $token =~ ^kv2:[0-9a-f]{16}:8$ ]]; then
    echo "txn-apply: plan returned an unexpected runtime_snapshot_token shape" >&2
    exit 1
fi
exec "$rbgp" --addr "$addr" config apply "$candidate" \
    --expected-runtime-snapshot-token "$token"
