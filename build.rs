fn main() {
    slint_build::compile("src/ui/main.slint").unwrap();

    // On Windows, embed the application manifest to declare PerMonitorV2 DPI awareness.
    // This ensures the application renders crisply on HiDPI displays (e.g. Surface Pro, 4K
    // monitors) by preventing Windows from applying legacy bitmap scaling (DPI virtualization).
    // Note: Slint handles per-monitor DPI scaling internally, but the manifest guarantees
    // the OS does not intercept and virtualize the process before Slint can act.
    #[cfg(windows)]
    embed_manifest::embed_manifest(embed_manifest::new_manifest("app.manifest"))
        .expect("Failed to embed Windows application manifest");
}
