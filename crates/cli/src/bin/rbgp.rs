// `#![deny(unsafe_code)]` lives on this bin root (not in `main.rs`, which is
// `include!`d here and so cannot carry an inner attribute). The `rbgp` bin pulls
// in the entire cli module tree, so this guards all cli code against `unsafe`.
#![deny(unsafe_code)]

include!("../main.rs");
