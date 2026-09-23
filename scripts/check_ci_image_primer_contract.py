#!/usr/bin/env python3
"""Fail closed when CI drifts from the failure classes its lab workflows guard.

Each rule has a mutation test in test_check_ci_image_primer_contract.py that
goes red when the rule is removed or weakened.

1. Verified downloads. Every archive digest in the CI surfaces is declared in
   the canonical .github/pinned-archives.sha256, and every entry there is in
   use. A workflow or action step that fetches verifies a SHA-256 in the same
   step; an installer script verifies what it fetches; nothing pipes network
   bytes into tar or a shell. A lab Dockerfile fetches only when its staged
   archive is absent and verifies before it extracts, and a lab job stages the
   same archive version before building that Dockerfile. Lab workflows never
   take bytes from the artifact service.
2. Action refs. Every external `uses:` is a reviewed version tag.
3. Permissions. Token scopes stay read-only apart from reviewed grants, and no
   workflow runs on pull_request_target.
4. Lab wiring. Every lab job needs prime_dev_image, and each run-interop-test
   call's topology and script belong to its label and to the job's name.
5. Aggregate result. Each lab workflow's `check` job runs always() and needs,
   and expects at run time, every other job in the workflow.

Rosters are derived from the workflows, so a lab job that follows the existing
pattern needs no edit here.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

WORKFLOWS = ("ci.yml", "audit.yml", "interop.yml", "kernel-dataplane.yml")
LAB_WORKFLOWS = ("interop.yml", "kernel-dataplane.yml")
MANIFEST = ".github/pinned-archives.sha256"
# External actions are pinned by reviewed version tag: no branch refs and no
# bare commit SHAs. Adding an action or moving to a new major edits this set.
PINS = frozenset(
    {
        "actions/cache@v4",
        "actions/cache/restore@v6",
        "actions/cache/save@v6",
        "actions/checkout@v7",
        "actions/upload-artifact@v7",
        "docker/build-push-action@v7",
        "docker/setup-buildx-action@v4",
        "dtolnay/rust-toolchain@v1",
        "EmbarkStudios/cargo-deny-action@v2",
        "rustsec/audit-check@v2.0.0",
        "Swatinem/rust-cache@v2",
    }
)
VERSION_TAG = re.compile(r"@v\d+(?:\.\d+){0,2}$")
# rustsec/audit-check posts its findings as a check-run.
WRITE_GRANTS = {"audit.yml": {"checks"}}
# ponytail: install-containerlab validates its .deb with dpkg-deb, not a pinned
# checksum; drop this exemption once it pins one.
UNPINNED_FETCH = {".github/actions/install-containerlab/action.yml"}

# A digest right after `sha256:` is an image or manifest reference, not an
# archive checksum; an all-zero digest is a self-test's deliberate mismatch.
DIGEST = re.compile(r"(?<![0-9a-f])(?<!sha256:)(?!0{64})[0-9a-f]{64}(?![0-9a-f])")
FETCH = re.compile(r"(?:^|[;&|(!]|\bthen|\bdo|\bif|\bRUN)\s*(?:sudo\s+)?(?:curl|wget)\s|^ADD\s+https?://", re.M)
STREAM = re.compile(r"\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:tar|sh|bash)\b")
VERIFY = re.compile(r"sha256sum\s+(?:--check|-c)\b")
EXTRACT = re.compile(r"\btar\s+(?:-\w*x\w*f|--extract\b.*?--file)\s+\"?([^\s\";]+)")
CHECKED = re.compile(r"[^;|&]*\|\s*sha256sum\s+(?:--check|-c)\b")
LAB_CALL = re.compile(
    r"(?ms)^        uses: \./\.github/actions/run-interop-test\n(.*?)(?=^      - |\Z)"
)
LAB_CALL_INPUT = re.compile(r"(?m)^          (label|topology|script): (.+)$")
LOCAL_ACTION = re.compile(r"uses:\s*\./(\.github/actions/[\w-]+)")
SCRIPT = re.compile(r"\.github/scripts/install-[\w-]+\.sh")
DOCKERFILE = re.compile(r"(?:-f\s+|file:\s+)(\S*Dockerfile[\w.-]*)")


def _jobs(text: str) -> dict[str, str]:
    body = text.split("\njobs:\n", 1)[1] if "\njobs:\n" in text else ""
    matches = list(re.finditer(r"(?m)^  ([\w-]+):\n", body))
    return {
        m.group(1): body[
            m.end() : matches[i + 1].start() if i + 1 < len(matches) else len(body)
        ]
        for i, m in enumerate(matches)
    }


def _list_needs(block: str) -> list[str]:
    flow = re.search(r"(?ms)^    needs: \[(.*?)\]\n", block)
    if flow:
        return [value.strip() for value in flow.group(1).split(",") if value.strip()]
    scalar = re.search(r"(?m)^    needs: ([\w-]+)$", block)
    if scalar:
        return [scalar.group(1)]
    match = re.search(r"(?m)^    needs:\n((?:      - [\w-]+\n)+)", block)
    return re.findall(r"(?m)^      - ([\w-]+)$", match.group(1)) if match else []


def _expected_jobs(block: str) -> list[str]:
    match = re.search(r"(?ms)^      EXPECTED_JOBS: >-\n(.*?)^    steps:\n", block)
    return match.group(1).split() if match else []


def _run_blocks(text: str):
    """Yield (line number, body) of every `run:` script in a workflow or action."""
    lines = text.splitlines()
    for number, line in enumerate(lines):
        match = re.match(r"( *)(- )?run:(.*)$", line)
        if not match:
            continue
        indent = len(match.group(1)) + len(match.group(2) or "")
        body = [match.group(3)]
        for following in lines[number + 1 :]:
            if following.strip() and len(following) - len(following.lstrip()) <= indent:
                break
            body.append(following)
        yield number + 1, "\n".join(body)


def _lab_token(label: str) -> str:
    """Scenario token of a lab label: ``M37+IP`` -> ``m37``, ``M43 crash-restart`` -> ``m43``."""
    return re.split(r"[ +-]", label, maxsplit=1)[0].lower()


def _check_lab_calls(prefix: str, job_name: str, job: str, errors: list[str]) -> None:
    calls = LAB_CALL.findall(job)
    if not calls:
        errors.append(f"{prefix}: has no run-interop-test call")
        return
    labels: set[str] = set()
    for call in calls:
        inputs = dict(LAB_CALL_INPUT.findall(call))
        missing = [key for key in ("label", "topology", "script") if key not in inputs]
        if missing:
            errors.append(f"{prefix}: run-interop-test call missing {', '.join(missing)}")
            return
        label = inputs["label"]
        # A space starts a descriptive suffix (``M43 crash-restart``); ``+`` and ``-``
        # join scenario variants (``M37+IP`` is the m37-ip job's own identifier).
        labels.add(label.split(" ", 1)[0].replace("+", "-").upper())
        token = _lab_token(label)
        if not inputs["topology"].startswith(f"tests/interop/{token}-"):
            errors.append(f"{prefix}: {label} topology drifted: {inputs['topology']}")
        if not inputs["script"].startswith(f"tests/interop/scripts/test-{token}-"):
            errors.append(f"{prefix}: {label} script drifted: {inputs['script']}")
    for token in job_name.split("_"):
        if token.upper() not in labels:
            errors.append(f"{prefix}: no run-interop-test call labelled {token.upper()}")


def _staged_version(step: str, action: str) -> str:
    """Archive version a stage-*-artifact step stages: its input or the action default."""
    explicit = re.search(r'(?m)^          version: "?([\w.]+)"?$', step)
    if explicit:
        return explicit.group(1)
    default = re.search(r'(?m)^  version:\n(?:    .*\n)*?    default: "?([\w.]+)"?', action)
    return default.group(1) if default else ""


def _check_staged_builds(
    prefix: str, job: str, root: Path, dockerfiles: dict[str, str], errors: list[str]
) -> None:
    """A build of a staged-archive Dockerfile follows a stage of the same version."""
    staged: list[tuple[str, str]] = []
    for step in re.split(r"(?m)^      - ", job):
        stage = re.search(r"uses: \./\.github/actions/stage-([\w-]+)-artifact", step)
        if stage:
            action = root / f".github/actions/stage-{stage.group(1)}-artifact/action.yml"
            text = action.read_text() if action.is_file() else ""
            staged.append((stage.group(1), _staged_version(step, text)))
        for path in DOCKERFILE.findall(step):
            source = dockerfiles.get(path, "")
            archive = re.search(r"(?m)^COPY ([\w-]+)-archive/", source)
            if not archive:
                continue
            arg = re.search(r"--build-arg \w*_VERSION=([\w.]+)", step)
            default = re.search(r"(?m)^(?:ARG|ENV) \w*_VERSION=([\w.]+)", source)
            version = (arg or default).group(1) if (arg or default) else "?"
            if (archive.group(1), version) not in staged:
                errors.append(
                    f"{prefix}: builds {path} without first staging "
                    f"{archive.group(1)} {version}"
                )


def _check_dockerfile(path: str, text: str, errors: list[str]) -> None:
    for instruction in text.replace("\\\n", " ").splitlines():
        if not FETCH.search(instruction):
            continue
        checked = [(m.end(), m.group(0)) for m in CHECKED.finditer(instruction)]
        extracts = list(EXTRACT.finditer(instruction))
        if not checked or any(
            not any(
                end < tar.start() and re.search(rf"\s{re.escape(tar.group(1))}(?![\w.])", seg)
                for end, seg in checked
            )
            for tar in extracts
        ):
            errors.append(f"{path}: fetch is not verified by sha256sum before extraction")
        if "[ ! -f" not in instruction:
            errors.append(f"{path}: fetch is not a fallback behind a staged-archive check")
        if STREAM.search(instruction):
            errors.append(f"{path}: streams network bytes into tar or a shell")


def _unverified_fetches(text: str) -> list[str]:
    """Functions holding installer fetches whose destination never reaches a checksum check.

    A fetch inside a download helper counts as verified when every call of the
    helper outside the self-test verifies the path it passed as the destination.
    """
    text = text.replace("\\\n", " ")
    functions = {
        m.group(1): m for m in re.finditer(r"(?ms)^([\w-]+)\(\) [{(]\n(.*?)^[})]$", text)
    }
    verifiers: set[str] = set()  # functions that check a SHA-256, directly or not
    for _ in range(len(functions) + 1):
        verified = re.compile(rf"{VERIFY.pattern}|\b(?:{'|'.join(verifiers) or '$^'})\b")
        verifiers = {n for n, m in functions.items() if verified.search(m.group(2))}

    def checked(destination: str, start: int) -> bool:
        lines = text[start:].splitlines()
        return any(destination in line and verified.search(line) for line in lines)

    unverified = []
    for fetch in FETCH.finditer(text):
        end = text.find("\n", fetch.end())
        destination = re.search(r"(?:--output|\s-[a-zA-Z]*o)\s+(\S+)", text[fetch.start() : end])
        if destination and checked(destination.group(1), end):
            continue
        owner = next((n for n, m in functions.items() if m.start(2) <= fetch.start() < m.end(2)), "")
        self_test = functions.get("self_test")
        calls = [
            call
            for call in re.finditer(rf"\b{re.escape(owner)}((?:\s+\"[^\"]*\")+)", text) if owner
            if not (self_test and self_test.start(2) <= call.start() < self_test.end(2))
        ]
        if not (calls and all(checked(c.group(1).split()[-1], c.end()) for c in calls)):
            unverified.append(owner or "top level")
    return unverified


def _check_permissions(name: str, text: str, errors: list[str]) -> None:
    if not re.search(r"(?m)^permissions:", text):
        errors.append(f"{name}: no top-level permissions block")
    if "pull_request_target" in text:
        errors.append(f"{name}: runs on pull_request_target")
    allowed = WRITE_GRANTS.get(name, set())
    for match in re.finditer(r"(?m)^( *)permissions:(.*)\n((?:\1  .*\n)*)", text):
        if "write" in match.group(2):
            errors.append(f"{name}: grants {match.group(2).strip()}")
        for scope, access in re.findall(r"(?m)^ *([\w-]+): *(\w+)", match.group(3)):
            if access == "write" and scope not in allowed:
                errors.append(f"{name}: grants {scope}: write")


def check(root: Path) -> list[str]:
    errors: list[str] = []
    texts = {
        f".github/workflows/{name}": (root / ".github/workflows" / name).read_text()
        for name in WORKFLOWS
    }
    # Every local action and installer script the workflows reach.
    pending = list(texts.values())
    while pending:
        for action in LOCAL_ACTION.findall(pending.pop()):
            relative = f"{action}/action.yml"
            if relative not in texts and (root / relative).is_file():
                texts[relative] = (root / relative).read_text()
                pending.append(texts[relative])
    scripts = {
        relative: (root / relative).read_text()
        for text in list(texts.values())
        for relative in SCRIPT.findall(text)
        if (root / relative).is_file()
    }
    # A build-push step without `file:` builds `<context>/Dockerfile`.
    defaults = [
        str(Path(context.group(1)) / "Dockerfile")
        for text in texts.values()
        for step in re.split(r"(?m)^ *- ", text)
        if "docker/build-push-action@" in step and "file:" not in step
        for context in [re.search(r"context: (\S+)", step)]
        if context
    ]
    dockerfiles = {
        relative: (root / relative).read_text()
        for relative in [*defaults, *(p for t in texts.values() for p in DOCKERFILE.findall(t))]
        if (root / relative).is_file()
    }

    # 1. Verified downloads.
    manifest = {}
    for line in (root / MANIFEST).read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            digest, _, archive = line.partition("  ")
            manifest[digest] = archive
    used: set[str] = set()
    for relative, text in {**texts, **scripts, **dockerfiles}.items():
        for match in DIGEST.finditer(text):
            used.add(match.group(0))
            if match.group(0) not in manifest:
                line = text.count("\n", 0, match.start()) + 1
                errors.append(f"{relative}:{line}: digest is not in {MANIFEST}")
    for digest, archive in manifest.items():
        if digest not in used:
            errors.append(f"{MANIFEST}: {archive} has no copy in the CI surfaces")
    for relative, text in texts.items():
        for line, body in _run_blocks(text):
            body = body.replace("\\\n", " ")
            if FETCH.search(body) and not VERIFY.search(body) and relative not in UNPINNED_FETCH:
                errors.append(f"{relative}:{line}: fetches without verifying a SHA-256")
            if STREAM.search(body):
                errors.append(f"{relative}:{line}: streams network bytes into tar or a shell")
    for relative, text in scripts.items():
        for owner in _unverified_fetches(text):
            errors.append(f"{relative}: fetch in {owner} is not verified by a SHA-256 check")
        if STREAM.search(text.replace("\\\n", " ")):
            errors.append(f"{relative}: streams network bytes into tar or a shell")
    for relative, text in dockerfiles.items():
        _check_dockerfile(relative, text, errors)

    for relative, text in texts.items():
        # 2. Action refs.
        for value in re.findall(r"(?m)^\s*(?:- )?uses:\s*(.+)$", text):
            ref = value.split("#", 1)[0].strip()
            if ref.startswith("./"):
                continue
            if not VERSION_TAG.search(ref):
                errors.append(f"{relative}: action ref is not a reviewed version tag: {ref}")
            elif ref not in PINS:
                errors.append(f"{relative}: action ref is not in the reviewed pin set: {ref}")
        # 3. Permissions.
        if relative.startswith(".github/workflows/"):
            _check_permissions(Path(relative).name, text, errors)

    for name in LAB_WORKFLOWS:
        text = texts[f".github/workflows/{name}"]
        if "actions/download-artifact@" in text:
            errors.append(f"{name}: a lab dependency flows through the artifact service")
        jobs = _jobs(text)
        # 4. Lab wiring.
        for job_name, job in jobs.items():
            if not (re.match(r"m\d", job_name) or LAB_CALL.search(job)):
                continue
            prefix = f"{name}:{job_name}"
            if "prime_dev_image" not in _list_needs(job):
                errors.append(f"{prefix}: does not need prime_dev_image")
            _check_lab_calls(prefix, job_name, job, errors)
            _check_staged_builds(prefix, job, root, dockerfiles, errors)
        # 5. Aggregate result.
        aggregate = jobs.get("check", "")
        others = set(jobs) - {"check"}
        if not re.search(r"(?m)^    if: \$\{\{ always\(\) \}\}$", aggregate):
            errors.append(f"{name}:check must run always()")
        for source, roster in (
            ("needs", set(_list_needs(aggregate))),
            ("EXPECTED_JOBS", set(_expected_jobs(aggregate))),
        ):
            if roster != others:
                missing = ", ".join(sorted(others - roster)) or "-"
                extra = ", ".join(sorted(roster - others)) or "-"
                errors.append(
                    f"{name}:check {source} drifted: missing {missing}; extra {extra}"
                )
    return errors


if __name__ == "__main__":
    failures = check(Path(__file__).resolve().parents[1])
    if failures:
        print("CI image-primer contract check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        raise SystemExit(1)
    print("CI image-primer contract OK")
