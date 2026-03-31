use std::{env, fs};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(key_update)");

    // `detect_key_update_at_build` — probe the *build-host* kernel version at
    // compile time.  When enabled the detection result is authoritative: if the
    // running kernel is >= 6.13 `cfg(key_update)` is set, otherwise it is NOT
    // set even when the `key_update` Cargo feature is on.  This is the
    // recommended mode for native builds / CI where the build host and the
    // target share the same kernel.
    //
    // Without `detect_key_update_at_build`, the `key_update` Cargo feature is
    // respected as-is (manual opt-in, useful for cross-compilation).
    let is_linux = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux");
    let detect = env::var_os("CARGO_FEATURE_DETECT_KEY_UPDATE_AT_BUILD").is_some();
    let feature = env::var_os("CARGO_FEATURE_KEY_UPDATE").is_some();

    let enabled = if detect && is_linux {
        matches!(read_kernel_version(), Some((maj, min)) if (maj, min) >= (6, 13))
    } else {
        feature
    };

    if enabled {
        println!("cargo:rustc-cfg=key_update");
    }
}

fn read_kernel_version() -> Option<(u32, u32)> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let mut parts = release.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}
