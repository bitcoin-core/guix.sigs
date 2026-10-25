"""Offline regression tests for pinned, data-only SHA256SUMS summaries.

No wallet keys, network requests, or privileged workflow credentials.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import subprocess
import unittest

import main as summary


RELEASE = "32.0rc4"
FILENAME = "noncodesigned.SHA256SUMS"
ARTIFACT = "bitcoin-32.0rc4-aarch64-linux-gnu.tar.gz"
HASH_A = "a" * 64
HASH_B = "b" * 64


class PinnedBlobTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.original_cwd = Path.cwd()
        self.addCleanup(os.chdir, self.original_cwd)
        self.repo = Path(self.temp.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        self.manifest = self.repo / RELEASE / "alice" / FILENAME
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text(f"{HASH_A}  {ARTIFACT}\n")
        self.git("add", ".")
        self.git("commit", "-qm", "trusted base")
        self.base = self.git("rev-parse", "HEAD").strip()
        os.chdir(self.repo)

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=True, capture_output=True, text=True
        ).stdout

    def commit_pr(self, value=HASH_B):
        self.git("checkout", "-qb", "pr")
        self.manifest.write_text(f"{value}  {ARTIFACT}\n")
        self.git("add", ".")
        self.git("commit", "-qm", "contributor-supplied SHA256SUMS")
        return self.git("rev-parse", "HEAD").strip()

    def test_pinned_snapshot_reads_pr_data_not_trusted_checkout(self):
        head = self.commit_pr()
        self.git("checkout", "-q", "main")
        changes = summary.changed_files(f"{self.base}..{head}")
        self.assertIn((RELEASE, FILENAME), changes)
        data = summary.read_files(changes, snapshot=head)
        self.assertEqual(data[RELEASE][FILENAME]["alice"][ARTIFACT], HASH_B)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.base)

    def test_force_push_does_not_change_pinned_snapshot(self):
        old_head = self.commit_pr()
        self.manifest.write_text(f"{HASH_A}  {ARTIFACT}\n")
        self.git("add", ".")
        self.git("commit", "-qm", "PR updated after review")
        new_head = self.git("rev-parse", "HEAD").strip()
        self.git("checkout", "-q", "main")
        changed = {(RELEASE, FILENAME)}
        self.assertEqual(
            summary.read_files(changed, snapshot=old_head)[RELEASE][FILENAME]["alice"][ARTIFACT],
            HASH_B
        )
        self.assertEqual(
            summary.read_files(changed, snapshot=new_head)[RELEASE][FILENAME]["alice"][ARTIFACT],
            HASH_A
        )

    def test_symlink_manifest_cannot_read_host_file(self):
        self.git("checkout", "-qb", "pr")
        linked = self.repo / RELEASE / "mallory" / FILENAME
        linked.parent.mkdir(parents=True)
        linked.symlink_to(self.repo / "outside.txt")
        (self.repo / "outside.txt").write_text("not manifest: never opened\n")
        self.git("add", ".")
        self.git("commit", "-qm", "malicious symlink in PR")
        head = self.git("rev-parse", "HEAD").strip()
        self.git("checkout", "-q", "main")
        data = summary.read_files({(RELEASE, FILENAME)}, snapshot=head)
        self.assertEqual(set(data[RELEASE][FILENAME]), {"alice"})

    def test_markdown_control_characters_are_rejected(self):
        self.git("checkout", "-qb", "pr")
        self.manifest.write_text(
            f"{HASH_A}  bitcoin-32.0rc4-\x60\x60\x60unexpected.md\n"
        )
        self.git("add", ".")
        self.git("commit", "-qm", "malformed artifact name")
        head = self.git("rev-parse", "HEAD").strip()
        self.git("checkout", "-q", "main")
        with self.assertRaisesRegex(ValueError, "unsafe manifest artifact name"):
            summary.read_files({(RELEASE, FILENAME)}, snapshot=head)

    def test_unpinned_ref_rejected(self):
        with self.assertRaisesRegex(ValueError, "immutable Git commit SHA"):
            summary.read_files({(RELEASE, FILENAME)}, snapshot="pr")

    def test_pr_diff_uses_merge_base_when_trusted_base_advances(self):
        head = self.commit_pr()
        self.git("checkout", "-q", "main")
        extra_release = "32.1rc1"
        other = self.repo / extra_release / "alice" / FILENAME
        other.parent.mkdir(parents=True)
        other.write_text(f"{HASH_A}  bitcoin-32.1rc1-x86_64.tar.gz\\n")
        self.git("add", ".")
        self.git("commit", "-qm", "trusted base advanced on another release")
        advanced = self.git("rev-parse", "HEAD").strip()
        # A two-dot diff wrongly attributes the base-only release to the PR.
        self.assertIn((extra_release, FILENAME), summary.changed_files(f"{advanced}..{head}"))
        # Three-dot compares the PR against the merge-base, as intended.
        self.assertEqual(summary.changed_files(f"{advanced}...{head}"), {(RELEASE, FILENAME)})

    def test_legacy_read_files_remains_functional(self):
        data = summary.read_files({(RELEASE, FILENAME)})
        self.assertEqual(data[RELEASE][FILENAME]["alice"][ARTIFACT], HASH_A)


if __name__ == "__main__":
    unittest.main(verbosity=2)
