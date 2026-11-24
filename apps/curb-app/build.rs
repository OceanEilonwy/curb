fn main() {
    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent-dark".into());
    slint_build::compile_with_config("ui/main.slint", config)
        .expect("Failed to compile Slint UI");

    #[cfg(windows)]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            let mut res = winresource::WindowsResource::new();
            res.set_icon("icons/icon.ico");
            res.set("ProductName", "Curb");
            res.set("FileDescription", "Curb Internet Limiter");
            res.compile().expect("Failed to compile Windows resources");
        }
    }
}
