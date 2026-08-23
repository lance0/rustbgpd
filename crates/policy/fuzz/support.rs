use std::net::Ipv4Addr;
use std::sync::Arc;

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use rustbgpd_policy::engine::{
    CommunityMatch, NamedPolicy, Policy, PolicyAction, PolicyChain, PolicyStatement, RouteContext,
    RouteModifications,
};
use rustbgpd_policy::ir::MatchExpr;
use rustbgpd_policy::rpol::compile_rpol;
use rustbgpd_policy::sets::SetStore;
use rustbgpd_wire::{AspaValidation, Ipv4Prefix, Prefix, RpkiValidation};

pub const MAX_POLICIES: usize = 8;
const MAX_STATEMENTS: usize = 6;

#[derive(Arbitrary, Debug)]
pub struct ChainRecipe {
    pub policies: u8,
    pub statements: u8,
    pub deny_at: u8,
    pub selector: u8,
}

#[derive(Debug)]
pub struct RouteRecipe {
    pub address: [u8; 4],
    pub prefix_len: u8,
    pub community: u16,
    pub local_pref: u16,
    pub med: u16,
}

pub fn toml_chain(recipe: &ChainRecipe) -> PolicyChain {
    let policy_count = usize::from(recipe.policies) % MAX_POLICIES + 1;
    let statement_count = usize::from(recipe.statements) % MAX_STATEMENTS + 1;
    let mut policies = Vec::with_capacity(policy_count);
    for policy_index in 0..policy_count {
        let mut entries = Vec::with_capacity(statement_count);
        for statement_index in 0..statement_count {
            let discriminator =
                (policy_index + statement_index + usize::from(recipe.selector)) as u32;
            entries.push(PolicyStatement {
                prefix: Some(v4([10, discriminator as u8, 0, 0], 16)),
                ge: Some(16),
                le: Some(28),
                action: if policy_index == usize::from(recipe.deny_at) % policy_count
                    && statement_index == usize::from(recipe.deny_at) % statement_count
                {
                    PolicyAction::Deny
                } else {
                    PolicyAction::Permit
                },
                match_community: vec![CommunityMatch::Standard {
                    value: 65_000_u32 << 16 | discriminator,
                }],
                match_as_path: None,
                match_neighbor_set: None,
                match_route_type: None,
                match_evpn_route_type: None,
                match_rpki_validation: None,
                match_aspa_validation: None,
                match_as_path_length_ge: None,
                match_as_path_length_le: None,
                match_local_pref_ge: Some(discriminator),
                match_local_pref_le: None,
                match_med_ge: None,
                match_med_le: Some(u32::from(u16::MAX)),
                match_next_hop: None,
                modifications: RouteModifications {
                    set_local_pref: Some(100 + discriminator),
                    ..RouteModifications::default()
                },
            });
        }
        policies.push(NamedPolicy {
            name: Some(format!("toml-{policy_index}")),
            policy: Policy {
                entries,
                default_action: PolicyAction::Permit,
            },
            rpol: None,
        });
    }
    let mut chain = PolicyChain::default();
    chain.policies = policies;
    chain
}

pub fn mixed_chain(recipe: &ChainRecipe) -> Option<PolicyChain> {
    let source = r#"
prefix-set p { 10.0.0.0/8 ge 16 le 28 }
community-set c { 65000:1, 65000:2 }
asn-set a { 64512, 64513 }
dataset asn-set external_asns
policy donor {
  term indexed {
    if route.prefix in p && route.communities in c && route.origin-as in a
       && route.as-path matches "^64512" && route.origin-as in external_asns { accept }
  }
  term fallback { accept }
}
"#;
    let donor = compile_rpol(source, &mut SetStore::new()).ok()?;
    assert_ids_resolve(&donor);
    let mut chain = toml_chain(recipe);
    let count = usize::from(recipe.policies).min(3) + 1;
    for index in 0..count {
        chain.policies.push(NamedPolicy::from_rpol(
            format!("rpol-{index}"),
            Arc::new(donor.clone()),
        ));
    }
    Some(chain)
}

pub fn assert_ids_resolve(compiled: &rustbgpd_policy::ir::CompiledChain) {
    for policy in &compiled.policies {
        for term in &policy.terms {
            assert!(all_ids_resolve(&term.guard, compiled));
        }
    }
}

fn all_ids_resolve(expr: &MatchExpr, compiled: &rustbgpd_policy::ir::CompiledChain) -> bool {
    let valid = std::cell::Cell::new(true);
    expr.any_node(&|node| {
        let resolved = match node {
            MatchExpr::PrefixInSet(id) => (id.0 as usize) < compiled.prefix_sets.len(),
            MatchExpr::CommunityInSet(id) | MatchExpr::LocalInCommunitySet { set: id, .. } => {
                (id.0 as usize) < compiled.community_sets.len()
            }
            MatchExpr::OriginAsInSet(id)
            | MatchExpr::PeerAsInSet(id)
            | MatchExpr::LocalInAsnSet { set: id, .. } => (id.0 as usize) < compiled.asn_sets.len(),
            MatchExpr::AsPathMatches(id) => (id.0 as usize) < compiled.as_path_regexes.len(),
            MatchExpr::InDataset { id, .. } => (id.0 as usize) < compiled.datasets.len(),
            _ => true,
        };
        valid.set(valid.get() && resolved);
        false
    });
    valid.get()
}

pub struct OwnedRoute {
    prefix: Prefix,
    communities: Vec<u32>,
    local_pref: u32,
    med: u32,
}

impl OwnedRoute {
    pub fn from_recipe(recipe: &RouteRecipe) -> Self {
        Self {
            prefix: v4(recipe.address, recipe.prefix_len.min(32)),
            communities: vec![65_000_u32 << 16 | u32::from(recipe.community)],
            local_pref: u32::from(recipe.local_pref),
            med: u32::from(recipe.med),
        }
    }

    pub fn context(&self) -> RouteContext<'_> {
        RouteContext {
            prefix: Some(self.prefix),
            next_hop: None,
            extended_communities: &[],
            communities: &self.communities,
            large_communities: &[],
            as_path_str: "",
            as_path: None,
            as_path_len: 0,
            origin_asn: None,
            validation_state: RpkiValidation::NotFound,
            aspa_state: AspaValidation::Unknown,
            peer_address: None,
            peer_asn: None,
            peer_group: None,
            route_type: None,
            family: None,
            evpn_route_type: None,
            local_pref: Some(self.local_pref),
            med: Some(self.med),
        }
    }
}

fn v4(address: [u8; 4], prefix_len: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(address), prefix_len))
}
