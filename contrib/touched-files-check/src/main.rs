use std::collections::{HashMap, HashSet};

fn check(touched_files: &str) -> Result<(Vec<&str>, HashSet<&str>), String> {
    let attestation_regex = regex::Regex::new("^([^/]+/[^/]+/[^/]+.SHA256SUMS)(|.asc)$").unwrap();
    let mut attestations = HashMap::new();
    let builder_key_regex = regex::Regex::new("^(builder-keys/[^/]+.gpg)$").unwrap();
    let mut builder_keys = HashSet::new();
    for line in touched_files.lines() {
        let (status, file) = {
            let mut l = line.split_whitespace();
            (l.next().unwrap(), l.next().unwrap())
        };
        if ["README.md", ".cirrus.yml", "contrib/"]
            .iter()
            .any(|ignore| file.starts_with(ignore))
        {
            continue;
        }
        if let Some(path) = attestation_regex.captures(file) {
            attestations
                .entry(path.get(1).unwrap().as_str())
                .or_insert_with(Vec::new)
                .push(path.get(2).unwrap().as_str());
            if status != "A" {
                return Err(format!(
                    "File status for attestation is not 'A' (for add): '{status}' '{file}'"
                ));
            }
        } else if let Some(path) = builder_key_regex.captures(file) {
            assert!(builder_keys.insert(path.get(1).unwrap().as_str()));
            if status != "A" && status != "M" {
                return Err(format!(
                    "File status for builder key is not 'A' (for add) or 'M' (for modified): '{status}' '{file}'"
                ));
            }
        } else {
            return Err(format!("Added unknown file '{file}'"));
        }
    }
    for (path, asc) in &attestations {
        if asc.len() != 2 {
            return Err(format!(
                "Missing SHA256SUMS.asc or SHA256SUMS file in {path}"
            ));
        }
    }
    Ok((attestations.into_keys().collect(), builder_keys))
}

fn main() {
    let diff_range = std::env::args()
        .nth(1)
        .expect("Missing diff_range argument");
    let git_diff = std::process::Command::new("git")
        .args(["diff", "--no-commit-id", "--name-status", &diff_range])
        .output()
        .expect("git error");
    assert!(git_diff.status.success());
    let touched_files = String::from_utf8(git_diff.stdout).expect("Invalid utf8");
    check(&touched_files).expect("check failed");
}

#[test]
fn test_check() {
    assert_eq!(check("M README.md"), Ok((vec![], HashSet::new())));
    assert_eq!(
        check("B 22.0/user/all.SHA256SUMS").unwrap_err(),
        "File status for attestation is not 'A' (for add): 'B' '22.0/user/all.SHA256SUMS'"
    );
    assert_eq!(
        check("A 22.0/user/all.SHA256SUMS\nA 22.0/user/all.SHA256SUMS.ask").unwrap_err(),
        "Added unknown file '22.0/user/all.SHA256SUMS.ask'"
    );
    assert_eq!(
        check("A 22.0/user/all.SHA256SUMS").unwrap_err(),
        "Missing SHA256SUMS.asc or SHA256SUMS file in 22.0/user/all.SHA256SUMS"
    );
    assert_eq!(
        check("A 22.0/user/all.SHA256SUMS\nA 22.0/user/all.SHA256SUMS.asc"),
        Ok((vec!["22.0/user/all.SHA256SUMS"], HashSet::new()))
    );
    assert_eq!(
        check("B builder-keys/user.gpg").unwrap_err(),
        "File status for builder key is not 'A' (for add) or 'M' (for modified): 'B' 'builder-keys/user.gpg'",
    );
    assert_eq!(
        check("M builder-keys/user.gpg"),
        Ok((vec![], HashSet::from(["builder-keys/user.gpg"])))
    );
}
