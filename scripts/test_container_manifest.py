#!/usr/bin/env python3
"""Exercise the release workflow's manifest checks with valid and broken indices."""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/container.yml"
PREDICATES = ["https://slsa.dev/provenance/v1", "https://spdx.dev/Document"]


def index():
    images = [
        {"digest": f"sha256:{digit * 64}", "platform": {"os": "linux", "architecture": arch}}
        for digit, arch in (("1", "amd64"), ("2", "arm64"))
    ]
    attestations = [
        {
            "digest": f"sha256:{digit * 64}",
            "platform": {"os": "unknown", "architecture": "unknown"},
            "annotations": {
                "vnd.docker.reference.type": "attestation-manifest",
                "vnd.docker.reference.digest": image["digest"],
            },
        }
        for digit, image in zip(("3", "4"), images)
    ]
    return {
        "digest": "sha256:" + "e" * 64,
        "annotations": {"org.opencontainers.image.description": "test image"},
        "manifests": images + attestations,
    }


def verification_script(workflow):
    step = workflow.split("      - name: Verify manifest platforms and tag identity\n", 1)[1]
    return textwrap.dedent(step.split("        run: |\n", 1)[1])


def verify(manifest, predicates=PREDICATES, script=None):
    with tempfile.TemporaryDirectory() as temporary:
        docker = Path(temporary) / "docker"
        docker.write_text(
            "#!/usr/bin/env python3\nimport os, sys\n"
            "print(os.environ['ATTESTATION'] if '--raw' in sys.argv else os.environ['MANIFEST'])\n"
        )
        docker.chmod(0o755)
        env = {
            **os.environ,
            "PATH": temporary + os.pathsep + os.environ["PATH"],
            "TAGS": "example:1\nexample:1.0",
            "REGISTRY": "example.invalid", "IMAGE_NAME": "test",
            "INDEX_DESCRIPTION": "test image",
            "MANIFEST": json.dumps(manifest),
            "ATTESTATION": json.dumps({"layers": [
                {"annotations": {"in-toto.io/predicate-type": value}} for value in predicates
            ]}),
        }
        return subprocess.run(
            ["bash", "-c", script or verification_script(WORKFLOW.read_text())],
            env=env, capture_output=True, text=True, check=False,
        )


class ContainerManifestTests(unittest.TestCase):
    def test_two_platforms_with_attestations_pass(self):
        result = verify(index())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_platform_or_attestation_descriptors_fail(self):
        base = index()
        mutations = {
            "missing attestation": lambda m: m["manifests"].pop(),
            "extra runtime": lambda m: m["manifests"].append(copy.deepcopy(m["manifests"][0])),
            "duplicate platform": lambda m: m["manifests"][1]["platform"].update(architecture="amd64"),
            "wrong os": lambda m: m["manifests"][1]["platform"].update(os="windows"),
            "unknown image": lambda m: m["manifests"][2]["annotations"].clear(),
            "wrong target": lambda m: m["manifests"][2]["annotations"].update({"vnd.docker.reference.digest": "sha256:" + "f" * 64}),
            "duplicate target": lambda m: m["manifests"][3]["annotations"].update({"vnd.docker.reference.digest": m["manifests"][0]["digest"]}),
            "invalid digest": lambda m: m["manifests"][0].update(digest="bad"),
            "wrong description": lambda m: m["annotations"].clear(),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                manifest = copy.deepcopy(base)
                mutate(manifest)
                result = verify(manifest)
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_both_attestation_types_are_required(self):
        for predicates in ([], PREDICATES[:1], PREDICATES[1:], PREDICATES + ["other"]):
            with self.subTest(predicates=predicates):
                result = verify(index(), predicates)
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_only_published_build_requests_attestations(self):
        workflow = WORKFLOW.read_text()
        load = workflow.split("      - name: Build native image for verification\n", 1)[1].split("      - name:", 1)[0]
        push = workflow.split("      - name: Push native image by digest\n", 1)[1].split("      - name:", 1)[0]
        self.assertIn("          provenance: false\n", load)
        self.assertIn("          sbom: false\n", load)
        self.assertIn("          provenance: mode=min,version=v1\n", push)
        self.assertRegex(push, r"sbom: generator=docker/buildkit-syft-scanner:[^@\s]+@sha256:[0-9a-f]{64}\n")


if __name__ == "__main__":
    unittest.main()
