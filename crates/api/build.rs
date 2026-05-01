fn main() -> Result<(), Box<dyn std::error::Error>> {
    // tonic 0.14 split prost-coupled codegen out into tonic-prost-build.
    // Same `compile_protos` / `configure()` surface, different crate;
    // tonic-build itself now generates only service-stub wiring.
    tonic_prost_build::compile_protos("../../proto/rustbgpd.proto")?;
    Ok(())
}
