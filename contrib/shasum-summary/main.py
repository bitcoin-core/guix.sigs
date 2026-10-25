import glob
import string
import argparse
import subprocess
import os
import re

USERNAME_ALPHABET = list(string.ascii_letters)
SYMBOLS = ["◆", "▞", "▄", "▀", "▌", "▐", "▚"]
SYMBOL_MATCH = "█"
SYMBOL_MISSING = "X"


def changed_files(diffrange):
    changed_files = set()
    p = subprocess.run(
        ["git", "diff", "--no-commit-id", "--name-only", diffrange],
        capture_output=True,
        text=True,
        check=True,
    )
    git_changed_files = p.stdout.strip().split("\n")
    for line in git_changed_files:
        # filter out changed files where the path does not start with a number
        # (as part of the release version) and signatures files (*.asc)
        if (
            not len(line) == 0
            and line[0] in string.digits
            and not line.endswith(".asc")
        ):
            path_parts = line.split("/")
            if len(path_parts) == 3:
                # <release>/<user>/<SHASUM file>
                release, _, filename = path_parts
                changed_files.add((release, filename))
    return changed_files


def read_files(changed_files, snapshot=None):
    """Summarize manifests from a trusted checkout or a pinned Git tree.

    A privileged workflow must never check out or execute the untrusted PR.
    In snapshot mode we read regular file blobs directly from Git objects:
    symlinks in a PR therefore cannot read files from the runner.
    """
    snapshot_files = None
    if snapshot is not None:
        if not re.fullmatch(r"[0-9a-f]{40}", snapshot):
            raise ValueError("snapshot must be an immutable Git commit SHA")
        result = subprocess.run(
            ["git", "ls-tree", "-r", "-z", snapshot],
            capture_output=True, check=True,
        )
        snapshot_files = []
        for entry in result.stdout.split(b"\x00"):
            if not entry:
                continue
            metadata, raw_path = entry.split(b"\t", 1)
            mode, kind, _ = metadata.decode("ascii").split(" ")
            if kind == "blob" and mode in {"100644", "100755"}:
                snapshot_files.append(os.fsdecode(raw_path))

    data = dict()
    for release, filename in changed_files:
        if snapshot_files is None:
            files = glob.glob(f"{release}/*/{filename}")
        else:
            # These are the only released manifest formats we summarize.
            if not re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", release):
                raise ValueError("unexpected release name")
            if filename not in {"all.SHA256SUMS", "noncodesigned.SHA256SUMS"}:
                continue
            files = [
                path for path in snapshot_files
                if len(path.split("/")) == 3
                and path.split("/")[0] == release
                and path.split("/")[2] == filename
            ]

        for file in files:
            user = file.split("/")[1]
            if snapshot_files is None:
                with open(file) as f:
                    lines = f.readlines()
            else:
                if not re.fullmatch(r"[A-Za-z0-9_.-]+", user):
                    raise ValueError("unexpected builder name")
                result = subprocess.run(
                    ["git", "cat-file", "blob", f"{snapshot}:{file}"],
                    capture_output=True, check=True,
                )
                if len(result.stdout) > 256_000:
                    raise ValueError("SHA256SUMS manifest too large")
                lines = result.stdout.decode("utf-8").splitlines()

            data.setdefault(release, {}).setdefault(filename, {})[user] = {}
            for line in lines:
                if not line.strip():
                    continue
                hashsum, artifact = line.strip().split("  ")
                if snapshot_files is not None:
                    # Bot comments are Markdown. Never let PR-controlled names
                    # inject formatting, mentions, links or executable HTML.
                    if not re.fullmatch(r"[a-fA-F0-9]{64}", hashsum):
                        raise ValueError("invalid manifest hash")
                    if not re.fullmatch(r"[A-Za-z0-9._+-]+", artifact):
                        raise ValueError("unsafe manifest artifact name")
                data[release][filename][user][artifact] = hashsum

                # Lint
                assert release in artifact, f"{filename}: {artifact} does not contain release version {release}"
                if "codesignatures" in artifact:
                    assert f"codesignatures-{release}" in artifact, f"{filename}: {artifact} signatures attached from incorrect tag"
    return data

def hash_to_symbol(hash, hashes):
    # all hashes match
    if len(hashes) == 1:
        return SYMBOL_MATCH
    # Sorting the hashes by occurrence count descending allows us to
    # display the most common hash (if any) with the same symbol.
    # If no hashes match, we essentially pick a random symbol.
    sorted_hashes = dict(sorted(hashes.items(), reverse=True, key=lambda item: item[1]))
    return SYMBOLS[list(sorted_hashes.keys()).index(hash) % len(SYMBOLS)]


def print_summaries(data):
    for release in sorted(data):
        for filename in data[release]:
            artifacts = dict()
            for user in data[release][filename]:
                for artifact in data[release][filename][user]:
                    if artifact not in artifacts:
                        artifacts[artifact] = dict()
                    hashsum = data[release][filename][user][artifact]
                    if hashsum not in artifacts[artifact]:
                        artifacts[artifact][hashsum] = 0
                    artifacts[artifact][hashsum] += 1

            SHORT_ARTIFACT_REPLACE = f"bitcoin-{release}-"
            artifact_max_length = max(
                [
                    len(artifact.replace(SHORT_ARTIFACT_REPLACE, ""))
                    for artifact in artifacts
                ]
            )

            text = f"`{filename}` summary for release `{release}`\n"
            text += "```\n"
            text += f"{'User (see mapping below)'.ljust(artifact_max_length, ' ')} {' '.join([USERNAME_ALPHABET[idx % len(USERNAME_ALPHABET)] for idx in range(len(data[release][filename]))]  )}\n"
            for artifact in sorted(artifacts):
                short_artifact = artifact.replace(SHORT_ARTIFACT_REPLACE, "")
                symbols = " ".join(
                    [
                        hash_to_symbol(
                            data[release][filename][user][artifact], artifacts[artifact]
                        )
                        if artifact in data[release][filename][user]
                        else SYMBOL_MISSING
                        for user in data[release][filename]
                    ]
                )
                text += f"{short_artifact.ljust(artifact_max_length, ' ')} {symbols}\n"
            text += "```\n\n"

            text += "<details><summary>Details</summary>\n"
            text += f"Symbols:\n\n"
            text += f"- all hashes match: `{SYMBOL_MATCH}`\n"
            text += f"- missing hash: `{SYMBOL_MISSING}`\n"
            text += f"- hash mismatch: one of `{'`, `'.join(SYMBOLS)}`\n\n"
            text += "Username mapping:\n"
            for idx, user in enumerate(data[release][filename]):
                text += f"- {USERNAME_ALPHABET[idx % len(USERNAME_ALPHABET)]}: {user}\n"
            text += "\n</details>\n"
            print(text)


def main():
    parser = argparse.ArgumentParser(description="Output a SHASUM summary to stdout")
    parser.add_argument(
        "diffrange",
        type=str,
        help="Only look at added or changed files in the diff-range",
    )
    parser.add_argument(
        "--snapshot",
        type=str,
        default=None,
        help="Read manifest blobs from this pinned Git commit, without checking out PR code",
    )
    args = parser.parse_args()

    changed_shasum_files = changed_files(args.diffrange)
    data = read_files(changed_shasum_files, snapshot=args.snapshot)
    print_summaries(data)


if __name__ == "__main__":
    main()
