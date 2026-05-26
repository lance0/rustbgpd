fn main() -> Result<(), Box<dyn std::error::Error>> {
    // tonic 0.14 split prost-coupled codegen out into tonic-prost-build.
    // Same `compile_protos` / `configure()` surface, different crate;
    // tonic-build itself now generates only service-stub wiring.
    //
    // The vendored gNMI protos import the Google well-known types
    // (`google/protobuf/{any,duration,descriptor}.proto`). Resolve them from
    // protoc-bin-vendored's bundled include directory instead of depending on
    // the host/Docker protoc shipping the well-known `.proto` files: the CI
    // image installs apt `protobuf-compiler` (the binary) without
    // `libprotobuf-dev` (the well-known protos), so the in-image build failed
    // with "google/protobuf/any.proto: File not found" while local builds — which
    // had the includes — passed. Putting the bundled include dir on the protoc
    // search path fixes codegen identically in every environment.
    let well_known_include = protoc_bin_vendored::include_path()?;
    tonic_prost_build::configure().compile_protos(
        &[
            "../../proto/rustbgpd.proto",
            "../../proto/github.com/openconfig/gnmi/proto/gnmi/gnmi.proto",
        ],
        &[
            "../../proto",
            well_known_include
                .to_str()
                .ok_or("protoc-bin-vendored include path is not valid UTF-8")?,
        ],
    )?;
    Ok(())
}
