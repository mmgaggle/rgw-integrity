// Link librados from LIBRADOS_DIR when it is not in the default search path,
// as with a ceph build tree's lib directory.
fn main() {
    println!("cargo:rerun-if-env-changed=LIBRADOS_DIR");
    if std::env::var_os("CARGO_FEATURE_CEPH").is_some() {
        if let Ok(dir) = std::env::var("LIBRADOS_DIR") {
            println!("cargo:rustc-link-search=native={dir}");
        }
        println!("cargo:rustc-link-lib=dylib=rados");
    }
}
