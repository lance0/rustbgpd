use std::collections::HashMap;

/// A single ASPA record: a customer ASN and its authorized provider ASNs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AspaRecord {
    pub customer_asn: u32,
    /// Authorized provider ASNs, sorted ascending and deduplicated.
    pub provider_asns: Vec<u32>,
}

/// Result of checking whether one AS is an authorized provider of another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAuth {
    /// The candidate AS is in the customer's provider set.
    ProviderPlus,
    /// The customer has an ASPA but the candidate AS is not in it.
    NotProviderPlus,
    /// No ASPA record exists for the customer AS.
    NoAttestation,
}

/// Lookup table for ASPA records, keyed by customer ASN.
#[derive(Debug, Clone)]
pub struct AspaTable {
    records: HashMap<u32, Vec<u32>>,
}

impl AspaTable {
    /// Build a table from a list of ASPA records.
    ///
    /// If multiple records exist for the same customer ASN, their provider
    /// sets are merged (union). This matches RTR cache behavior where
    /// multiple CAs may issue ASPAs for the same customer.
    #[must_use]
    pub fn new(records: Vec<AspaRecord>) -> Self {
        let mut map: HashMap<u32, Vec<u32>> = HashMap::new();
        for record in records {
            let entry = map.entry(record.customer_asn).or_default();
            for asn in record.provider_asns {
                if let Err(pos) = entry.binary_search(&asn) {
                    entry.insert(pos, asn);
                }
            }
        }
        Self { records: map }
    }

    /// Check whether `provider` is an authorized provider of `customer`.
    #[must_use]
    pub fn authorized(&self, customer: u32, provider: u32) -> ProviderAuth {
        match self.records.get(&customer) {
            None => ProviderAuth::NoAttestation,
            Some(providers) => {
                if providers.binary_search(&provider).is_ok() {
                    ProviderAuth::ProviderPlus
                } else {
                    ProviderAuth::NotProviderPlus
                }
            }
        }
    }

    /// Number of customer ASNs with ASPA records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl PartialEq for AspaTable {
    fn eq(&self, other: &Self) -> bool {
        self.records == other.records
    }
}

impl Eq for AspaTable {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_returns_no_attestation() {
        let table = AspaTable::new(vec![]);
        assert_eq!(table.authorized(65001, 65002), ProviderAuth::NoAttestation);
        assert!(table.is_empty());
    }

    #[test]
    fn provider_found() {
        let table = AspaTable::new(vec![AspaRecord {
            customer_asn: 65001,
            provider_asns: vec![65002, 65003],
        }]);
        assert_eq!(table.authorized(65001, 65002), ProviderAuth::ProviderPlus);
        assert_eq!(table.authorized(65001, 65003), ProviderAuth::ProviderPlus);
    }

    #[test]
    fn provider_not_found() {
        let table = AspaTable::new(vec![AspaRecord {
            customer_asn: 65001,
            provider_asns: vec![65002],
        }]);
        assert_eq!(
            table.authorized(65001, 65099),
            ProviderAuth::NotProviderPlus
        );
    }

    #[test]
    fn unknown_customer_returns_no_attestation() {
        let table = AspaTable::new(vec![AspaRecord {
            customer_asn: 65001,
            provider_asns: vec![65002],
        }]);
        assert_eq!(table.authorized(65099, 65002), ProviderAuth::NoAttestation);
    }

    #[test]
    fn merge_duplicate_customer_records() {
        let table = AspaTable::new(vec![
            AspaRecord {
                customer_asn: 65001,
                provider_asns: vec![65002, 65003],
            },
            AspaRecord {
                customer_asn: 65001,
                provider_asns: vec![65003, 65004],
            },
        ]);
        assert_eq!(table.authorized(65001, 65002), ProviderAuth::ProviderPlus);
        assert_eq!(table.authorized(65001, 65003), ProviderAuth::ProviderPlus);
        assert_eq!(table.authorized(65001, 65004), ProviderAuth::ProviderPlus);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn unsorted_providers_are_sorted() {
        let table = AspaTable::new(vec![AspaRecord {
            customer_asn: 65001,
            provider_asns: vec![65005, 65002, 65003],
        }]);
        assert_eq!(table.authorized(65001, 65002), ProviderAuth::ProviderPlus);
        assert_eq!(table.authorized(65001, 65005), ProviderAuth::ProviderPlus);
    }

    #[test]
    fn equality() {
        let t1 = AspaTable::new(vec![AspaRecord {
            customer_asn: 65001,
            provider_asns: vec![65002],
        }]);
        let t2 = AspaTable::new(vec![AspaRecord {
            customer_asn: 65001,
            provider_asns: vec![65002],
        }]);
        assert_eq!(t1, t2);
    }
}
