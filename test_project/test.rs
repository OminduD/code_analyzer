// test.rs
fn main() {
    // VULNERABILITY RUST001
    unsafe {
        println!("Unsafe block executed!");
    }

    // VULNERABILITY RUST002
    let _cmd = std::process::Command::new("sh").arg("-c").arg("echo Hello");
}
