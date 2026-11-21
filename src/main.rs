//! mask — native (Rust) build of the PII pseudonymization gateway.

fn main() {
    std::process::exit(mask::cli::main());
}
