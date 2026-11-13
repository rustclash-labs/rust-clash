fn main() {
    println!("cargo:rerun-if-changed=icons/icon.ico");

    #[cfg(feature = "desktop")]
    tauri_build::build();

    #[cfg(all(not(feature = "desktop"), windows))]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = tauri_winres::WindowsResource::new();
        res.set_icon("icons/icon.ico")
            .set("ProductName", "RustClash")
            .set("CompanyName", "RustClash Labs")
            .set("FileDescription", "RustClash Desktop Proxy & TUN Client");
        res.compile()
            .expect("failed to compile Windows PE icon & version resource for tauri-app");
    }
}
