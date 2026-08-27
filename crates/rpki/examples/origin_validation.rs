use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_rpki::{VrpEntry, VrpTable};
use rustbgpd_wire::{Ipv4Prefix, Prefix, RpkiValidation};

fn main() {
    let table = VrpTable::new(vec![VrpEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
        prefix_len: 24,
        max_len: 24,
        origin_asn: 64_496,
    }]);
    let route = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));

    assert_eq!(table.validate(&route, 64_496), RpkiValidation::Valid);
    println!("{route} is valid for AS64496");
}
