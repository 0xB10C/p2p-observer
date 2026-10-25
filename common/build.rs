fn main() {
    prost_build::compile_protos(&["proto/events.proto", "proto/archive.proto"], &["proto/"])
        .unwrap();
}
