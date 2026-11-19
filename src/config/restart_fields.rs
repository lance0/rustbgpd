//! Field-level diagnostics for startup-owned RPKI, BMP and MRT configuration.
//! Compare credentials in place. Only explicitly printable fields are serialized.

use super::{BmpConfig, ConfigFieldImpact, FieldChange, MrtConfig, RpkiConfig, json_config_value};

#[derive(Default)]
struct SectionFields(Vec<FieldChange>);

impl SectionFields {
    // The section structs differ. Keep the warning if a future schema field
    // has not yet been classified for display.
    fn finish(mut self, section: &'static str) -> Vec<FieldChange> {
        if self.0.is_empty() {
            self.0.push(FieldChange::withheld_restart_field(section));
        }
        self.0
    }

    fn value<T: PartialEq + serde::Serialize>(
        &mut self,
        prefix: &str,
        field: &str,
        old: Option<&T>,
        new: Option<&T>,
    ) {
        if old == new {
            return;
        }
        let old = json_config_value(&old);
        let new = json_config_value(&new);
        // An unset optional field on a newly added or removed row stays unset.
        if old != new {
            self.0.push(FieldChange {
                field: format!("{prefix}{field}").into(),
                old,
                new,
                impact: Some(ConfigFieldImpact::RestartRequired),
                annotation: None,
                values_summarized: false,
            });
        }
    }

    fn name_only<T: PartialEq + ?Sized>(
        &mut self,
        prefix: &str,
        field: &str,
        old: Option<&T>,
        new: Option<&T>,
    ) {
        if old != new {
            self.0.push(FieldChange::withheld_restart_field(format!(
                "{prefix}{field}"
            )));
        }
    }
}

macro_rules! fields {
    ($diff:ident, $prefix:expr, $old:ident, $new:ident; $($method:ident $field:ident),+ $(,)?) => {
        $(
            $diff.$method(
                $prefix,
                stringify!($field),
                $old.map(|entry| &entry.$field),
                $new.map(|entry| &entry.$field),
            );
        )+
    };
}

fn changed_entries<'a, T: PartialEq>(
    old: &'a [T],
    new: &'a [T],
) -> impl Iterator<Item = (usize, Option<&'a T>, Option<&'a T>)> {
    (0..old.len().max(new.len()))
        .map(|i| (i, old.get(i), new.get(i)))
        .filter(|(_, a, b)| a != b)
}

pub(crate) fn rpki_restart_required_changes(
    old: Option<&RpkiConfig>,
    new: Option<&RpkiConfig>,
) -> Vec<FieldChange> {
    if old == new {
        return Vec::new();
    }
    let mut diff = SectionFields::default();
    fields!(diff, "", old, new;
        value local_revalidation, value max_records_per_cache, value max_records_total);
    let old_caches = old.map_or(&[][..], |r| r.cache_servers.as_slice());
    let new_caches = new.map_or(&[][..], |r| r.cache_servers.as_slice());
    for (i, old, new) in changed_entries(old_caches, new_caches) {
        let cache = format!("cache_servers[{i}].");
        fields!(diff, &cache, old, new;
            value address, value refresh_interval, value retry_interval,
            value expire_interval, value max_expire_interval);
        diff.name_only(
            &cache,
            "md5_password",
            old.and_then(|c| c.md5_password.as_deref()),
            new.and_then(|c| c.md5_password.as_deref()),
        );
        let old_keys = old
            .and_then(|c| c.tcp_ao.as_ref())
            .map_or(&[][..], |k| k.0.as_slice());
        let new_keys = new
            .and_then(|c| c.tcp_ao.as_ref())
            .map_or(&[][..], |k| k.0.as_slice());
        for (j, old, new) in changed_entries(old_keys, new_keys) {
            let key = format!("{cache}tcp_ao[{j}].");
            fields!(diff, &key, old, new;
                name_only key, value send_id, value recv_id, value algorithm,
                value preferred, value deprecated);
        }
    }
    diff.finish("[rpki]")
}

pub(crate) fn bmp_restart_required_changes(
    old: Option<&BmpConfig>,
    new: Option<&BmpConfig>,
) -> Vec<FieldChange> {
    if old == new {
        return Vec::new();
    }
    let mut diff = SectionFields::default();
    fields!(diff, "", old, new; name_only sys_name, name_only sys_descr);
    let old_collectors = old.map_or(&[][..], |b| b.collectors.as_slice());
    let new_collectors = new.map_or(&[][..], |b| b.collectors.as_slice());
    for (i, old, new) in changed_entries(old_collectors, new_collectors) {
        let collector = format!("collectors[{i}].");
        fields!(diff, &collector, old, new;
            value address, value reconnect_interval, value monitor, value version,
            value on_identity_conflict);
    }
    diff.finish("[bmp]")
}

pub(crate) fn mrt_restart_required_changes(
    old: Option<&MrtConfig>,
    new: Option<&MrtConfig>,
) -> Vec<FieldChange> {
    if old == new {
        return Vec::new();
    }
    let mut diff = SectionFields::default();
    fields!(diff, "", old, new;
        name_only output_dir, value dump_interval, value compress, name_only file_prefix,
        value max_files);
    diff.finish("[mrt]")
}
