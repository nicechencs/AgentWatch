//! The only file in this crate that names a platform.
//! Later tasks assemble real collectors here.

/// Confirms the daemon links every collector crate it is allowed to depend on.
pub fn wired() -> bool {
    // Referencing each crate keeps the dependency graph honest without calling
    // into platform code. Non-target collector crates export nothing yet.
    let _ = (
        std::any::type_name::<aw_core::Placeholder>(),
        std::any::type_name::<aw_pipeline::Placeholder>(),
        std::any::type_name::<aw_store::Placeholder>(),
        std::any::type_name::<aw_proxy::Placeholder>(),
        std::any::type_name::<aw_agent_adapters::Placeholder>(),
        std::any::type_name::<aw_collector_poll::Placeholder>(),
    );

    #[cfg(target_os = "linux")]
    let _ = std::any::type_name::<aw_collector_linux::LinuxCollector>();
    #[cfg(target_os = "windows")]
    let _ = std::any::type_name::<aw_collector_windows::WindowsCollector>();
    #[cfg(target_os = "macos")]
    let _ = std::any::type_name::<aw_collector_macos::MacosCollector>();

    true
}
