use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // tonic-prost-build emits no rerun-if-changed, and Cargo's default scan
    // covers only this package, so the shared proto outside it would leave
    // stale generated code. Declaring any path disables that scan, so list
    // everything this script reads.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=proto/gobgp.proto");
    println!("cargo:rerun-if-changed=../../proto/rustbgpd.proto");
    let well_known_include = protoc_bin_vendored::include_path()?;
    // GoBGP v3 API, vendored unmodified. Default stubs answer every RPC the
    // bridge does not implement with UNIMPLEMENTED. The generated client is
    // used by the integration tests.
    let gobgp = PathBuf::from("proto");
    tonic_prost_build::configure()
        .generate_default_stubs(true)
        .compile_protos(
            &[gobgp.join("gobgp.proto")],
            &[gobgp, well_known_include.clone()],
        )?;
    // rustbgpd's own API, client side only.
    let rustbgpd = PathBuf::from("../../proto");
    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(
            &[rustbgpd.join("rustbgpd.proto")],
            &[rustbgpd, well_known_include],
        )?;
    Ok(())
}
