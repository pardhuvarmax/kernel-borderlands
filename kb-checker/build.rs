fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .compile(
            &["../kb-control-plane/proto/kb.proto", "proto/health.proto"],
            &["../kb-control-plane/proto/", "proto/"],
        )?;
    Ok(())
}
