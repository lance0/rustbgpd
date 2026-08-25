import hashlib, importlib.util, json, subprocess, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("verify", HERE / "verify_session_notification_receipt.py")
V = importlib.util.module_from_spec(spec); spec.loader.exec_module(V)

def lines(highs=None):
    highs = highs or range(1, 11)
    return "\n".join(
        "session_notification_receipt," + ",".join((
            f"stage={stage}", f"round={round_}", f"sessions={sessions}",
            f"completions={completions}", f"target={target}", "current=0", f"high_watermark={high}",
            "parse_errors=0", "drain_wait_us=1",
        )) for (stage, round_, sessions, completions, target), high in zip(V.ROWS, highs)
    ) + "\n"

class VerifyTests(unittest.TestCase):
    def test_rows_accept_exact_contract_and_reject_mutations(self):
        self.assertEqual(len(V.parse_rows(lines())), 10)
        mutations = [
            lines().replace("current=0", "current=1", 1),
            lines().replace("sessions=650", "sessions=651", 1),
            lines().replace("target=28600", "target=-1", 1),
            lines().replace("stage=round_start", "stage=extra", 1),
            lines() + lines().splitlines()[0] + "\n",
            lines().replace(",current=0", ",label=x,current=0", 1),
            lines([1, 2, 3, 4, 3, 6, 7, 8, 9, 10]),
            lines([0] + list(range(2, 11))),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation[:80]), self.assertRaises(ValueError):
                V.parse_rows(mutation)

    def test_full_receipt_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); repo = root / "repo"
            subprocess.run(["git", "clone", "-q", HERE.parents[2], repo], check=True)
            commit = subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()
            tree = subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD^{tree}"], text=True).strip()
            binary = root / "reloadstall"; binary.write_bytes(b"binary")
            (root / "harness.log").write_text(lines())
            (root / "initial.csv").write_text("first_exact_bitmap,mode=flapstorm,peers=700,total=400400,per_peer=572,expected=399828,completed=700,min_unique=399828,max_unique=399828\n")
            (root / "checkpoints.csv").write_text(lines())
            (root / "flapstorm.csv").write_text("".join(f"flapstorm_csv,{i},700,50,400400,28600,0,0,0,0,0,0,0,700,0\n" for i in range(1, 4)))
            raw = root.parent / f"{root.name}-raw"; run = raw / "rustbgpd"; run.mkdir(parents=True); self.addCleanup(lambda: __import__("shutil").rmtree(raw, ignore_errors=True))
            (run / "reloadstall.log").write_text((root / "initial.csv").read_text() + lines() + (root / "flapstorm.csv").read_text())
            (run / "daemon.log").write_text("healthy\n"); (run / "status").write_text("pass\n")
            (run / "rss.csv").write_text("rss\n"); (run / "scenario").mkdir(); (run / "scenario" / "config.toml").write_text("scenario\n")
            raw_text = "\n".join((run / name).read_text() for name in ("reloadstall.log", "daemon.log", "status")).lower()
            (root / "daemon-summary.json").write_text(json.dumps({"notification_send_errors":0,"correctness_errors":0,"raw_logs_sha256":hashlib.sha256(raw_text.encode()).hexdigest()}))
            (root / "README.md").write_text("fixture\n"); (root / "verification.json").write_text(json.dumps({"commit":commit,"verdict":"verified"}))
            names = {name: V.sha(root / name) for name in V.FILES}
            (root / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(names.items())))
            receipt = {
                "repo": str(repo), "commit": commit, "tree": tree, "base": V.BASE, "base_tree": V.BASE_TREE,
                "binaries": {name: {"path": str(binary), "sha256": V.sha(binary)} for name in ("daemon", "harness")},
                "sources": {name: {"path": str(repo / path), "sha256": V.sha(repo / path)} for name, path in V.SOURCE_PATHS.items()},
                "artifacts": names, "workload": V.WORKLOAD, "command": ["bash", "bench/scale/matrix/run-matrix.sh", "rustbgpd"],
                "environment": {"N_PEERS":"700", "TOTAL_PREFIXES":"400400", "RELOADS":"0", "CONTROL_SECS":"30", "FLAPSTORM":"50", "ARTIFACTS_DIR":str(raw), "RELOADSTALL_SESSION_NOTIFICATION_METRICS_ADDR": "127.0.0.1:9179"},
                "system": {"rustc":"1", "cargo":"1", "kernel":"k", "cpu":"c", "captured_at":"2026-08-25T00:00:00Z"},
                "raw_campaign_root": {"path": str(raw), "sha256": V.directory_digest(raw)},
            }
            (root / "receipt.json").write_text(json.dumps(receipt))
            V.verify(root)
            mutations = [
                ("commit", "A" * 40), ("tree", "0" * 40), ("base", "0" * 40), ("base", subprocess.check_output(["git", "-C", repo, "rev-parse", V.BASE + "^"], text=True).strip()), ("base_tree", "0" * 40),
                ("workload", {**V.WORKLOAD, "peers": 699}),
                ("environment", {}), ("raw_root_sha256", "0" * 64),
                ("artifacts", {**names, "harness.log": "0" * 64}),
                ("binaries", {}), ("sources", {}), ("system", {}),
                ("raw_campaign_root", {"path": str(raw), "sha256": "0" * 64}),
            ]
            for key, value in mutations:
                broken = dict(receipt); broken[key] = value
                (root / "receipt.json").write_text(json.dumps(broken))
                with self.subTest(key=key), self.assertRaises(Exception): V.verify(root)
            copied = root / "same.rs"; copied.write_bytes((repo / V.SOURCE_PATHS["harness_main"]).read_bytes())
            broken = json.loads(json.dumps(receipt)); broken["sources"]["harness_main"]["path"] = str(copied)
            (root / "receipt.json").write_text(json.dumps(broken))
            with self.assertRaises(ValueError): V.verify(root)
            source = repo / V.SOURCE_PATHS["harness_main"]; original = source.read_bytes(); source.write_bytes(original + b"\n")
            (root / "receipt.json").write_text(json.dumps(receipt))
            with self.assertRaises(ValueError): V.verify(root)
            source.write_bytes(original)
            def reseal():
                receipt["artifacts"] = {name: V.sha(root / name) for name in V.FILES}
                (root / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(receipt["artifacts"].items())))
                receipt["raw_campaign_root"]["sha256"] = V.directory_digest(raw)
                (root / "receipt.json").write_text(json.dumps(receipt))
            (root / "checkpoints.csv").write_text(lines().replace("drain_wait_us=1", "drain_wait_us=2", 1)); reseal()
            with self.assertRaises(ValueError): V.verify(root)
            (root / "checkpoints.csv").write_text(lines()); (run / "status").write_text("PASS\n"); reseal()
            with self.assertRaises(ValueError): V.verify(root)
            (run / "status").write_text("pass\n"); (run / "daemon.log").write_text("generic send failed\n"); reseal()
            with self.assertRaises(ValueError): V.verify(root)
            (run / "daemon.log").write_text("healthy\n"); (raw / "daemon.log").write_text("wrong location\n"); (run / "daemon.log").unlink(); reseal()
            with self.assertRaises(ValueError): V.verify(root)

if __name__ == "__main__": unittest.main()
