//! Host prerequisites are advisory: links and DAD may recover after startup.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::{AcceptedConfigSnapshot, Config};
use crate::host_ipv6::{self, Finding};

type Findings = BTreeMap<String, Vec<Finding>>;

pub(crate) fn inspect(config: &Config) -> Findings {
    let interfaces = config
        .neighbors
        .all()
        .filter_map(|neighbor| {
            let interface = neighbor.interface.as_deref()?;
            Some((interface.to_owned(), neighbor.address.is_empty()))
        })
        .collect::<BTreeMap<_, _>>();
    if interfaces.is_empty() {
        return Findings::new();
    }
    let inspector = host_ipv6::Inspector::new();
    interfaces
        .into_iter()
        .filter_map(|(interface, interface_only)| {
            let findings = inspector.inspect(&interface, interface_only)?;
            Some((interface, findings))
        })
        .collect()
}

pub(crate) fn check(config: &Config) -> usize {
    let findings = inspect(config);
    let mut count = 0;
    for (interface, issues) in findings {
        for issue in issues {
            crate::print_framed_warning(
                &format!("interface {interface}: {}", issue.condition),
                &issue.detail,
            );
            count += 1;
        }
    }
    count
}

pub(crate) fn spawn(
    mut accepted: watch::Receiver<Arc<AcceptedConfigSnapshot>>,
) -> tokio_util::task::AbortOnDropHandle<()> {
    tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        let mut previous = Findings::new();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                changed = accepted.changed() => { if changed.is_err() { return; } }
            }
            let snapshot = Arc::clone(&accepted.borrow_and_update());
            let Ok(current) =
                tokio::task::spawn_blocking(move || inspect(snapshot.config_ref())).await
            else {
                warn!("host IPv6 prerequisite inspection task failed");
                continue;
            };
            report_changes(&previous, &current);
            previous = current;
        }
    }))
}

fn report_changes(previous: &Findings, current: &Findings) {
    for (interface, issues) in current {
        for issue in issues {
            if !previous
                .get(interface)
                .is_some_and(|old| old.contains(issue))
            {
                warn!(interface, condition = issue.condition, detail = %issue.detail, "host IPv6 prerequisite warning");
            }
        }
        if issues.is_empty() && previous.get(interface).is_some_and(|old| !old.is_empty()) {
            info!(interface, "host IPv6 prerequisites recovered");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek};

    use super::*;

    #[test]
    fn host_ipv6_monitor_warns_once_until_recovery_or_change() {
        let mut log = tempfile::tempfile().unwrap();
        let writer = log.try_clone().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.try_clone().unwrap())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let missing = BTreeMap::from([(
            "swp1".to_owned(),
            vec![Finding {
                condition: "link_local_missing",
                detail: "missing".to_owned(),
                unusable: true,
            }],
        )]);
        let tentative = BTreeMap::from([(
            "swp1".to_owned(),
            vec![Finding {
                condition: "link_local_tentative",
                detail: "tentative".to_owned(),
                unusable: true,
            }],
        )]);
        let ready = BTreeMap::from([("swp1".to_owned(), Vec::new())]);
        report_changes(&Findings::new(), &missing);
        report_changes(&missing, &missing);
        report_changes(&missing, &tentative);
        report_changes(&tentative, &ready);
        report_changes(&ready, &ready);
        report_changes(&ready, &missing);
        report_changes(&missing, &Findings::new());
        log.rewind().unwrap();
        let mut text = String::new();
        log.read_to_string(&mut text).unwrap();
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 4, "{text}");
        assert_eq!(rows[0]["fields"]["condition"], "link_local_missing");
        assert_eq!(rows[1]["fields"]["condition"], "link_local_tentative");
        assert_eq!(
            rows[2]["fields"]["message"],
            "host IPv6 prerequisites recovered"
        );
        assert_eq!(rows[3]["fields"]["condition"], "link_local_missing");
        assert!(rows.iter().all(|row| row["fields"]["interface"] == "swp1"));
    }
}
