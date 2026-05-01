fn main() -> Result<(), Box<dyn std::error::Error>> {
    // tonic 0.14 split prost-coupled codegen out into tonic-prost-build.
    // Same `configure()` builder surface (build_server / build_client /
    // compile_protos) — only the crate name changed.
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["../../proto/rustbgpd.proto"], &["../../proto"])?;
    Ok(())
}
