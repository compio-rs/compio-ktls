use std::{env, fs};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(key_update)");

    // `detect_key_update_at_build` — when enabled **and** the build host is
    // Linux, probe the kernel version at compile time.  If the running kernel
    // is >= 6.14, `cfg(key_update)` is set; otherwise it is NOT set even when
    // the `key_update` Cargo feature is on.  This is the recommended mode for
    // native builds / CI where the build host and the target share the same
    // kernel.
    //
    // When the build host is not Linux (e.g. cross-compiling from macOS) or
    // `detect_key_update_at_build` is not enabled, the `key_update` Cargo
    // feature is respected as-is (manual opt-in).
    let detect = env::var_os("CARGO_FEATURE_DETECT_KEY_UPDATE_AT_BUILD").is_some();
    let feature = env::var_os("CARGO_FEATURE_KEY_UPDATE").is_some();

    let enabled = if detect && cfg!(target_os = "linux") {
        matches!(read_kernel_version(), Some((maj, min)) if (maj, min) >= (6, 14))
    } else {
        feature
    };

    if enabled {
        println!("cargo:rustc-cfg=key_update");
    }
}

fn read_kernel_version() -> Option<(u32, u32)> {
    let path = "/proc/sys/kernel/osrelease";
    // Re-run when the kernel version changes (e.g. reboot into a different
    // kernel).  procfs mtime reflects boot time, so Cargo will notice.
    println!("cargo:rerun-if-changed={path}");
    let release = fs::read_to_string(path).ok()?;
    let mut parts = release.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}
