#!/usr/bin/env python3
"""Snapshot candidate inputs without building or running the fixture."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

repo = Path('/tmp/campaign-source')
out = Path(sys.argv[1])
out.mkdir()  # Refuse an existing snapshot, including an existing symlink.


def git(*args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


paths = sorted(set(git('ls-files', '-z', '--cached', '--others',
                      '--exclude-standard').split(b'\0')) - {b''})
sources = {}
for raw in paths:
    relative = raw.decode('utf-8')
    path = repo / relative
    if not path.exists():
        sources[relative] = {'missing': True}
        continue
    sources[relative] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    if path.is_symlink():
        sources[relative]['symlink'] = str(path.readlink())
(out / 'source.json').write_text(json.dumps(sources, sort_keys=True, indent=2) + '\n')
for name, args in {
    'git-head': ('rev-parse', 'HEAD'),
    'git-status': ('status', '--porcelain=v1', '--untracked-files=all'),
    'git-diff.patch': ('diff', '--binary', '--no-ext-diff', 'HEAD'),
}.items():
    (out / name).write_bytes(git(*args))
