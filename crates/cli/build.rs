fn main() -> Result<(), Box<dyn std::error::Error>> {
    // tonic 0.14 split prost-coupled codegen out into tonic-prost-build.
    // Same `configure()` builder surface (build_server / build_client /
    // compile_protos) — only the crate name changed.
    let proto_root = std::path::PathBuf::from("../../proto");
    let well_known_include = protoc_bin_vendored::include_path()?;
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &[proto_root.join("rustbgpd.proto")],
            &[proto_root, well_known_include],
        )?;
    Ok(())
}
