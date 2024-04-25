import glob
import string
import argparse
import subprocess

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


def read_files(changed_files):
    data = dict()
    for release, filename in changed_files:
        if release not in data:
            data[release] = {}
        files = glob.glob(f"{release}/*/{filename}")
        for file in files:
            user = file.split("/")[1]
            with open(file) as f:
                if filename not in data[release]:
                    data[release][filename] = {}
                data[release][filename][user] = {}

                for line in f.readlines():
                    if len(line.strip()) == 0:
                        continue

                    hashsum, artifact = line.strip().split("  ")
                    data[release][filename][user][artifact] = hashsum
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
    args = parser.parse_args()

    changed_shasum_files = changed_files(args.diffrange)
    data = read_files(changed_shasum_files)
    print_summaries(data)


if __name__ == "__main__":
    main()
