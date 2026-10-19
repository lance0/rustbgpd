use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
