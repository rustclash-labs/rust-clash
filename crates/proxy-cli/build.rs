fn main() {
    println!("cargo:rerun-if-changed=../tauri-app/icons/icon.ico");

    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = tauri_winres::WindowsResource::new();
        res.set_icon("../tauri-app/icons/icon.ico")
            .set("ProductName", "RustClash")
            .set("CompanyName", "RustClash Labs")
            .set("FileDescription", "RustClash Proxy Kernel CLI");
        res.compile()
            .expect("failed to compile Windows PE icon & version resource for proxy-cli");
    }
}
