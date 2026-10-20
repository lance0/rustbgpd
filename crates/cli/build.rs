fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The shared proto lives outside this package, so Cargo's default scan
    // misses it; declaring paths replaces that scan, so list both inputs.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../proto/rustbgpd.proto");
    // tonic 0.14 split prost-coupled codegen out into tonic-prost-build.
    // Same `configure()` builder surface (build_server / build_client /
    // compile_protos) — only the crate name changed.
    let proto_root = std::path::PathBuf::from("../../proto");
    let well_known_include = protoc_bin_vendored::include_path()?;
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        // Match the API's pointer-sized optional views.
        .boxed(".rustbgpd.v1.VpnRouteEntry.prefix_sid")
        .boxed(".rustbgpd.v1.EvpnRouteEntry.prefix_sid")
        .boxed(".rustbgpd.v1.EvpnRouteEntry.smet")
        .compile_protos(
            &[proto_root.join("rustbgpd.proto")],
            &[proto_root, well_known_include],
        )?;
    Ok(())
}
