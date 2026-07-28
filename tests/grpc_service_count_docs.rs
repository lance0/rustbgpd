use std::{fs, path::PathBuf, process::Command};

fn proto_tokens(input: &str) -> Vec<String> {
    let mut chars = input.chars().peekable();
    let mut tokens = Vec::new();
    while let Some(c) = chars.next() {
        if c == '/' && chars.peek() == Some(&'/') {
            chars.by_ref().find(|next| *next == '\n');
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(next) = chars.next() {
                if next == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
            }
        } else if c == '"' || c == '\'' {
            while let Some(next) = chars.next() {
                if next == '\\' {
                    chars.next();
                } else if next == c {
                    break;
                }
            }
        } else if c == '{' {
            tokens.push(c.to_string());
        } else if c == '_' || c.is_ascii_alphabetic() {
            let mut token = c.to_string();
            while chars
                .peek()
                .is_some_and(|next| *next == '_' || next.is_ascii_alphanumeric())
            {
                token.push(chars.next().unwrap());
            }
            tokens.push(token);
        }
    }
    tokens
}

fn service_names(path: &std::path::Path) -> Vec<String> {
    proto_tokens(&fs::read_to_string(path).unwrap())
        .windows(3)
        .filter(|window| window[0] == "service" && window[2] == "{")
        .map(|window| window[1].clone())
        .collect()
}

fn normalized(block: &str) -> Vec<String> {
    block
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

fn number(word: &str) -> Option<usize> {
    const WORDS: &str = "zero one two three four five six seven eight nine ten eleven twelve \
        thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty";
    word.parse().ok().or_else(|| {
        WORDS
            .split_whitespace()
            .position(|candidate| candidate == word)
    })
}

fn find_patterns(words: &[String], before: &[&str], after: &[&str]) -> Vec<(usize, usize)> {
    words
        .windows(before.len() + 1 + after.len())
        .enumerate()
        .filter_map(|(index, window)| {
            (window[..before.len()]
                .iter()
                .map(String::as_str)
                .eq(before.iter().copied())
                && window[before.len() + 1..]
                    .iter()
                    .map(String::as_str)
                    .eq(after.iter().copied()))
            .then(|| number(&window[before.len()]).map(|value| (index, value)))
            .flatten()
        })
        .collect()
}

fn totals(words: &[String]) -> Vec<usize> {
    [
        (&["grpc", "surface", "across"][..], &["services"][..]),
        (
            &["grpc", "control", "surface", "across"][..],
            &["services"][..],
        ),
        (&["grpc", "server", "tonic"][..], &["services"][..]),
        (&["grpc"][..], &["services"][..]),
    ]
    .into_iter()
    .flat_map(|(before, after)| find_patterns(words, before, after))
    .map(|(_, value)| value)
    .collect()
}

fn natives(words: &[String], is_total: bool) -> Vec<usize> {
    let none = &[][..];
    let mut claims: Vec<_> = [
        (none, &["native", "rustbgpd", "v1", "services"][..]),
        (none, &["native", "rustbgpd", "v1", "grpc", "services"][..]),
        (none, &["separate", "grpc", "services"][..]),
    ]
    .into_iter()
    .flat_map(|(before, after)| find_patterns(words, before, after))
    .collect();
    if words.iter().any(|word| word == "grpc") {
        claims.extend(find_patterns(words, &[], &["service", "split"]));
    }
    if is_total {
        for (index, window) in words.windows(2).enumerate() {
            if window[1] == "native"
                && !claims.iter().any(|(seen, _)| *seen == index)
                && let Some(value) = number(&window[0])
            {
                claims.push((index, value));
            }
        }
    }
    claims.into_iter().map(|(_, value)| value).collect()
}

#[test]
fn documented_grpc_service_counts_match_proto_inventory() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let native = service_names(&root.join("proto/rustbgpd.proto")).len();
    let gnmi = root.join("proto/github.com/openconfig/gnmi/proto/gnmi/gnmi.proto");
    assert_eq!(service_names(&gnmi), ["gNMI"]);
    let total = native + 1;

    let output = Command::new("git")
        .args(["-C", root.to_str().unwrap(), "ls-files", "-z", "--", "*.md"])
        .output()
        .unwrap();
    assert!(output.status.success(), "git ls-files failed");

    let mut total_claims = 0;
    let mut native_claims = 0;
    let mut mismatches = Vec::new();
    let paths = output.stdout.split(|byte| *byte == 0);
    for path in paths.filter(|path| !path.is_empty()) {
        let relative = String::from_utf8(path.to_vec()).unwrap();
        let markdown = fs::read_to_string(root.join(&relative)).unwrap();
        for block in markdown.split("\n\n") {
            let words = normalized(block);
            let observed_totals = totals(&words);
            for observed in &observed_totals {
                total_claims += 1;
                if *observed != total {
                    mismatches.push(format!(
                        "{relative}: observed {observed}, classification total, proto-derived expected {total}"
                    ));
                }
            }
            for observed in natives(&words, !observed_totals.is_empty()) {
                native_claims += 1;
                if observed != native {
                    mismatches.push(format!(
                        "{relative}: observed {observed}, classification native, proto-derived expected {native}"
                    ));
                }
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "stale gRPC service count claims:\n{}",
        mismatches.join("\n")
    );
    assert_eq!(total_claims, 5, "expected five total-service claims");
    assert_eq!(native_claims, 8, "expected eight native-service claims");
}
