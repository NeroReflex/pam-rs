fn main() {
    // Tell cargo to tell rustc to link the system pam
    // shared library.
    println!("cargo:rustc-link-lib=pam");

    // pam_misc is only supported on Linux afaik
    if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=pam_misc");
    }
}
