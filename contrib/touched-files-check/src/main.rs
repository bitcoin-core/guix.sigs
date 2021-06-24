fn check(touched_files: &str) -> Result<(), String> {
    let path_regex = regex::Regex::new("^([^/]+/[^/]+/[^/]+.SHA256SUMS)(|.asc)$").unwrap();
    let mut attestations = std::collections::HashMap::new();
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
        if status != "A" {
            return Err(format!(
                "File status is not 'A' (for add): '{status}' '{file}'"
            ));
        }
        if let Some(path) = path_regex.captures(file) {
            attestations
                .entry(path.get(1).unwrap().as_str())
                .or_insert(Vec::new())
                .push(path.get(2).unwrap().as_str());
        } else {
            return Err(format!("Added unknown file '{file}'"));
        }
    }
    if attestations.len() > 1 {
        return Err(format!("Added files need to be under the same path prefix"));
    }
    for (path, asc) in attestations {
        if asc.len() != 2 {
            return Err(format!(
                "Missing SHA256SUMS.asc or SHA256SUMS file in {path}"
            ));
        }
    }
    Ok(())
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
    assert!(check("M README.md").is_ok());
    assert_eq!(
        check("B 22.0/user/all.SHA256SUMS").unwrap_err(),
        "File status is not 'A' (for add): 'B' '22.0/user/all.SHA256SUMS'"
    );
    assert_eq!(
        check("A 22.0/user/all.SHA256SUMS\nA 22.0/user/all.SHA256SUMS.ask").unwrap_err(),
        "Added unknown file '22.0/user/all.SHA256SUMS.ask'"
    );
    assert_eq!(
        check("A 22.0/user/all.SHA256SUMS").unwrap_err(),
        "Missing SHA256SUMS.asc or SHA256SUMS file in 22.0/user/all.SHA256SUMS"
    );
    assert!(check("A 22.0/user/all.SHA256SUMS\nA 22.0/user/all.SHA256SUMS.asc").is_ok());
}
