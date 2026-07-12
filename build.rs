fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").expect("No target OS specified");
    if target_os == "macos" {
        bindgen_vmnet()
    }
}

fn bindgen_vmnet() {
    println!("cargo:rustc-link-lib=framework=vmnet");
    // TODO VMNET: use bindgen as a standalone tool, cleanup its output
    let sysroot = std::process::Command::new("xcrun")
        .arg("--show-sdk-path")
        .stdout(std::process::Stdio::piped())
        .output()
        .expect("Unable to get SDK root");
    let sysroot = String::from_utf8(sysroot.stdout).expect("Failed to decode SDK path from xcrun");
    let bindings = bindgen::Builder::default()
        .header_contents("include.h", "#include <vmnet/vmnet.h>\n")
        .clang_arg(format!("-isysroot{}", sysroot.trim()))
        .allowlist_function("vmnet_start_interface")
        .allowlist_function("vmnet_stop_interface")
        .allowlist_function("vmnet_interface_set_event_callback")
        .allowlist_function("vmnet_read")
        .allowlist_function("vmnet_write")
        .allowlist_var("vmnet_mtu_key")
        .allowlist_var("vmnet_enable_checksum_offload_key")
        .allowlist_var("vmnet_enable_tso_key")
        .allowlist_var("vmnet_operation_mode_key")
        .allowlist_var("vmnet_allocate_mac_address_key")
        .allowlist_var("vmnet_mac_address_key")
        .allowlist_var("vmnet_estimated_packets_available_key")
        .allowlist_var("VMNET_HOST_MODE")
        .allowlist_var("VMNET_SUCCESS")
        .allowlist_var("VMNET_INTERFACE_PACKETS_AVAILABLE")
        .allowlist_function("xpc_dictionary_create")
        .allowlist_function("xpc_uint64_create")
        .allowlist_function("xpc_bool_create")
        .allowlist_function("xpc_dictionary_get_string")
        .allowlist_function("xpc_dictionary_get_uint64")
        .allowlist_function("dispatch_get_global_queue")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
