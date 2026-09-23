use std::env;
use std::fs;
use std::path::PathBuf;

const SNIFFER_SOURCES: [&str; 4] = ["sniffer.c", "capture_loop.c", "pcap_replay.c", "device.c"];

fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo sets manifest dir"));
    let project = crate_dir.join("../..");
    build_sniffer(&project.join("sniffer-c"));
    generate_header(&crate_dir, &project.join("contracts/core_ffi.h"));
}

fn build_sniffer(root: &std::path::Path) {
    let windows = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let mut build = cc::Build::new();
    build.include(root.join("include")).warnings(true).warnings_into_errors(true);
    for src in SNIFFER_SOURCES {
        build.file(root.join("src").join(src));
    }
    if windows {
        build
            .file(root.join("src/win_npcap.c"))
            .flag_if_supported("/std:c17")
            .define("_CRT_SECURE_NO_WARNINGS", None);
    } else {
        build
            .file(root.join("src/posix_pcap.c"))
            .flag_if_supported("-std=c17")
            .define("_POSIX_C_SOURCE", "200809L");
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=pthread");
    }
    build.compile("sniffer");
    println!("cargo:rerun-if-changed={}", root.join("src").display());
    println!("cargo:rerun-if-changed={}", root.join("include").display());
}

fn generate_header(crate_dir: &std::path::Path, out: &std::path::Path) {
    let config = cbindgen::Config::from_file(crate_dir.join("cbindgen.toml")).expect("cbindgen.toml is valid");
    let bindings = cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen can parse core-ffi");

    let mut fresh = Vec::new();
    bindings.write(&mut fresh);
    // ayni icerikse yazma, yoksa her build'de dosya degisir
    if fs::read(out).ok().as_deref() != Some(fresh.as_slice()) {
        fs::create_dir_all(out.parent().expect("header has a parent dir")).expect("contracts dir");
        fs::write(out, &fresh).expect("write core_ffi.h");
    }
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
