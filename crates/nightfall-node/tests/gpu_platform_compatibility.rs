use nightfall_node::runtime::GPU_AVAILABLE;

#[test]
fn gpu_availability_matches_platform() {
    let supported = cfg!(any(target_os = "macos", windows, target_os = "linux"));
    assert_eq!(GPU_AVAILABLE, cfg!(feature = "gpu") && supported);
}
