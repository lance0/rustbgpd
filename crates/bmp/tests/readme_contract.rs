use rustbgpd_bmp::BmpEvent;

fn section_between_exact_headings(markdown: &str, start: &str, end: &str) -> String {
    let lines: Vec<_> = markdown.lines().collect();
    let starts: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (*line == start).then_some(index))
        .collect();
    let ends: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (*line == end).then_some(index))
        .collect();

    assert_eq!(starts.len(), 1, "expected exactly one {start} heading");
    assert_eq!(ends.len(), 1, "expected exactly one {end} heading");
    assert!(starts[0] < ends[0], "{start} must precede {end}");

    lines[starts[0] + 1..ends[0]].join("\n")
}

fn expected_manager_roster(names: &[&str]) -> String {
    let (last, leading) = names.split_last().expect("event roster must not be empty");
    let roster = match leading {
        [] => format!("`{last}`"),
        [only] => format!("`{only}` and `{last}`"),
        _ => format!(
            "{}, and `{last}`",
            leading
                .iter()
                .map(|name| format!("`{name}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };

    format!("`BmpManager` receives every `BmpEvent` variant through an `mpsc` channel: {roster}.")
}

macro_rules! assert_bmp_event_roster {
    ($($variant:ident),+ $(,)?) => {{
        let assert_exhaustive = |event: &BmpEvent| match event {
            $(BmpEvent::$variant { .. } => (),)+
        };
        let _ = assert_exhaustive;

        expected_manager_roster(&[$(stringify!($variant)),+])
    }};
}

#[test]
fn architecture_lists_every_manager_event_input() {
    let readme = include_str!("../README.md").replace("\r\n", "\n");
    let architecture = section_between_exact_headings(&readme, "## Architecture", "## License");
    let paragraphs: Vec<_> = architecture
        .split("\n\n")
        .map(str::trim)
        .filter(|paragraph| !paragraph.is_empty())
        .collect();
    let manager_rosters: Vec<_> = paragraphs
        .iter()
        .filter(|paragraph| {
            paragraph.starts_with("`BmpManager` receives every `BmpEvent` variant ")
        })
        .collect();

    assert_eq!(
        manager_rosters.len(),
        1,
        "Architecture must contain exactly one BmpEvent roster paragraph"
    );

    let expected = assert_bmp_event_roster!(
        PeerUp,
        PeerDown,
        RouteMonitoring,
        StatsReport,
        LocRibRouteMonitoring,
        LocRibStats,
    );
    let actual = manager_rosters[0]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    assert_eq!(actual, expected);
}
