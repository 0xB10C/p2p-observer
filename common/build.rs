fn main() {
    prost_build::compile_protos(&["proto/events.proto"], &["proto/"]).unwrap();
}
