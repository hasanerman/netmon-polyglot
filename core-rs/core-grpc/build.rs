use std::path::PathBuf;

fn main() {
    let contracts = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
    let proto = contracts.join("analytics.proto");
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc is available");
    std::env::set_var("PROTOC", protoc);
    tonic_prost_build::configure()
        .compile_protos(&[&proto], &[&contracts])
        .expect("analytics.proto compiles");
    println!("cargo:rerun-if-changed={}", proto.display());
}
