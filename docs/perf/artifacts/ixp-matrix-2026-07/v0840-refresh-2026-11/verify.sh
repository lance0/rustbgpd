#!/bin/sh
# Re-check the artifact set against MANIFEST. Exits nonzero on any mismatch.
cd "$(dirname "$0")" && exec sha256sum -c --quiet MANIFEST
