"""Public bundle boundaries that complement the original join/gate regressions."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import recompute as r


class BundleTests(unittest.TestCase):
    def test_clock_rejection_cannot_be_promoted_by_wrapper(self):
        with patch.object(r.publication, 'read', return_value={'cross_process_clock_qualified': False}):
            with self.assertRaisesRegex(ValueError, 'publication clock rejected'):
                r.probe_rows(None, None, None, 'probe')

    def test_actual_plan(self):
        r.validate_plan(json.loads((r.ROOT/'plan.json').read_text()))

    def test_wrong_source_rejected(self):
        plan = json.loads((r.ROOT/'plan.json').read_text())
        plan['source_commit'] = '0'*40
        with self.assertRaisesRegex(ValueError, 'wrong source'):
            r.validate_plan(plan)

    def test_relaxed_gate_rejected(self):
        plan = json.loads((r.ROOT/'plan.json').read_text())
        plan['overhead']['maximum_regression_percent'] = 3
        with self.assertRaisesRegex(ValueError, 'overhead bar'):
            r.validate_plan(plan)

    def test_missing_file_hash_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path/'native.csv').write_text('native\n')
            (path/'SHA256SUMS').write_text('')
            with self.assertRaisesRegex(ValueError, 'cover every artifact'):
                r.verify_hashes(path)

    def test_altered_hashed_native_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path/'native.csv').write_text('native\n')
            (path/'SHA256SUMS').write_text(r.digest(path/'native.csv')+'  native.csv\n')
            r.verify_hashes(path)
            (path/'native.csv').write_text('different\n')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                r.verify_hashes(path)

    def test_traversal_rejected(self):
        with self.assertRaisesRegex(ValueError, 'local basename'):
            r.relative_file(r.ROOT, '../README.md')

    def test_full_receipt_and_original_reader_equivalence(self):
        result = r.recompute()
        self.assertFalse(result['qualification']['overhead_qualified'])
        self.assertTrue(result['qualification']['all_joins_and_clocks_qualified'])
        self.assertTrue(result['original_reader_equal'])
        self.assertEqual(result['joined_first_frames'], 8400)

    def test_changed_native_extraction_rejected(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as out:
            root = Path(tmp)
            shutil.copy(r.ROOT/'native-records.tar.gz', root)
            manifest = json.loads((r.ROOT/'native-extraction.json').read_text())
            name = next(iter(manifest['files']))
            manifest['files'][name]['public_sha256'] = '0'*64
            (root/'native-extraction.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'extract hash mismatch'):
                r.extract_native(root, Path(out))

    def test_unsafe_native_entries_rejected(self):
        import io
        import tarfile
        for name, link in [('../outside', False), ('01-control/link', True)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with tarfile.open(root/'native-records.tar.gz', 'w:gz') as archive:
                    member = tarfile.TarInfo(name)
                    if link:
                        member.type = tarfile.SYMTYPE
                        member.linkname = '/etc/passwd'
                        archive.addfile(member)
                    else:
                        member.size = 1
                        archive.addfile(member, io.BytesIO(b'x'))
                (root/'native-extraction.json').write_text(json.dumps({'files': {name: {}}}))
                with self.assertRaisesRegex(ValueError, 'unsafe native archive'):
                    r.extract_native(root, root/'output')
                self.assertFalse((root/'output').exists())

    def test_missing_native_member_rejected(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as out:
            root = Path(tmp)
            shutil.copy(r.ROOT/'native-records.tar.gz', root)
            manifest = json.loads((r.ROOT/'native-extraction.json').read_text())
            manifest['files'].pop(next(iter(manifest['files'])))
            (root/'native-extraction.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'archive coverage'):
                r.extract_native(root, Path(out))


if __name__ == '__main__':
    unittest.main()
