//! Collector wiring is selected by `aw-platform`.
//! Later tasks assemble real collectors through that boundary.

/// Confirms the daemon links every collector crate it is allowed to depend on.
pub fn wired() -> bool {
    // Referencing each crate keeps the dependency graph honest without calling
    // into platform code. Non-target collector crates export nothing yet.
    let _ = (
        // P0-CORE-01 replaced the aw-core stub type with the event model.
        std::any::type_name::<aw_core::RawEvent>(),
        std::any::type_name::<aw_pipeline::Placeholder>(),
        std::any::type_name::<aw_store::Placeholder>(),
        std::any::type_name::<aw_proxy::Placeholder>(),
        std::any::type_name::<aw_agent_adapters::Placeholder>(),
        std::any::type_name::<aw_collector_poll::Placeholder>(),
    );

    // `aw-platform` is the sole target selector.  Naming its selected OS
    // implementation here keeps this shared assembly file free of target
    // branches while still ensuring the current platform is linked.
    let _ = aw_platform::platform().os();

    true
}
