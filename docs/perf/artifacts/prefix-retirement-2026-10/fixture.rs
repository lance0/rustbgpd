#[path = "baseline.rs"]
mod prefix_map;
use std::{hint::black_box, io::{self, Write}, sync::Mutex, time::{Duration, Instant}};
use rustbgpd_wire::{Ipv4Prefix, Prefix};
use smallvec::SmallVec;
fn main() {
    let mut map = prefix_map::FamilyPrefixMap::<SmallVec<[(u32,u32);1]>>::default();
    for index in 0..400_400u32 {
        let addr = std::net::Ipv4Addr::from(0x0a00_0000 + index * 256);
        map.entry_or_default(Prefix::V4(Ipv4Prefix::new(addr, 24))).push((0,index));
    }
    let last_service = Mutex::new(Instant::now());
    let mut count = 0u64;
    println!("READY"); io::stdout().flush().unwrap();
    io::stdin().read_line(&mut String::new()).unwrap();
    map.retire_with(&mut || {
        count += 1;
        let mut last = last_service.lock().unwrap();
        if last.elapsed() >= Duration::from_millis(25) {
            *last = Instant::now();
            black_box(&mut last);
        }
    });
    assert!(map.iter_from(None).next().is_none());
    println!("DONE {count}"); io::stdout().flush().unwrap();
    io::stdin().read_line(&mut String::new()).unwrap();
}
