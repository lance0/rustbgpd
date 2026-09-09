use std::collections::BTreeMap;

use rustbgpd_wire::notification::{NotificationCode, description};

#[test]
fn documented_notification_registry_matches_descriptions() {
    let doc = include_str!("../../../docs/reference/notification-registry.md");
    let table = doc
        .split_once("<!-- notification-descriptions:start -->")
        .unwrap()
        .1
        .split_once("<!-- notification-descriptions:end -->")
        .unwrap()
        .0;
    let mut descriptions = BTreeMap::new();
    for row in table.lines().filter(|line| line.starts_with('|')).skip(2) {
        let cells: Vec<_> = row.trim_matches('|').split('|').map(str::trim).collect();
        assert_eq!(cells.len(), 5, "malformed registry row: {row}");
        assert!(
            cells.iter().all(|cell| !cell.is_empty()),
            "blank cell: {row}"
        );
        let code: u8 = cells[0].parse().unwrap();
        let subcode: u8 = cells[1].parse().unwrap();
        assert!(matches!(cells[3], "active" | "deprecated"), "{row}");
        assert!(!matches!(cells[2], "Unknown" | "Unknown Error Code"));
        assert!(
            descriptions.insert((code, subcode), cells[2]).is_none(),
            "duplicate: {row}"
        );
    }
    assert!(!descriptions.is_empty(), "registry table is empty");
    for code in u8::MIN..=u8::MAX {
        let notification_code = NotificationCode::from_u8(code);
        assert_eq!(notification_code.as_u8(), code);
        for subcode in u8::MIN..=u8::MAX {
            let actual = description(notification_code, subcode);
            if let Some(expected) = descriptions.get(&(code, subcode)) {
                assert_eq!(actual, *expected, "registered pair {code}/{subcode}");
            } else {
                assert!(
                    matches!(actual, "Unknown" | "Unknown Error Code"),
                    "undocumented pair {code}/{subcode}: {actual}"
                );
            }
        }
    }
    // Description coverage must not change the decoder's public enum variants.
    for code in [7, 9] {
        assert_eq!(
            NotificationCode::from_u8(code),
            NotificationCode::Unknown(code)
        );
    }
}
