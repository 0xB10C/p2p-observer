fn main() {
    let mut config = prost_build::Config::new();
    // The websocket tool serves events to browsers as JSON. Deriving serde on
    // the generated types keeps that a plain `serde_json::to_string` of the
    // same struct the observer publishes, with no hand-written mirror to drift.
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config
        .compile_protos(&["proto/events.proto", "proto/archive.proto"], &["proto/"])
        .expect("failed to compile the protobuf schemas in proto/");
    println!("cargo:rerun-if-changed=proto/events.proto");
    println!("cargo:rerun-if-changed=proto/archive.proto");
}
