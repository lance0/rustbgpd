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
    // The dial-out proto imports the gnmi package compiled above. Compile it
    // separately with `extern_path` so its references resolve to the flat
    // `crate::gnmi` module instead of prost's package-relative `super::…`
    // chain (which assumes package-shaped module nesting we don't use), and
    // into its own out_dir so this invocation cannot clobber the gnmi/
    // gnmi_ext files the first invocation just wrote.
    let dialout_out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("dialout");
    std::fs::create_dir_all(&dialout_out_dir)?;
    tonic_prost_build::configure()
        .extern_path(".gnmi", "crate::gnmi")
        .out_dir(&dialout_out_dir)
        .compile_protos(
            &["../../proto/rustbgpd_dialout.proto"],
            &[
                "../../proto",
                well_known_include
                    .to_str()
                    .ok_or("protoc-bin-vendored include path is not valid UTF-8")?,
            ],
        )?;
    Ok(())
}
