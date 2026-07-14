#!/bin/sh
# cargo install bindgen-cli
set -e

INCLUDE_FILE="$(mktemp -u).h"
echo '#include <vmnet/vmnet.h>' > $INCLUDE_FILE
xcrun bindgen \
  --no-derive-copy --no-derive-debug\
  --allowlist-function vmnet_start_interface\
  --allowlist-function vmnet_stop_interface\
  --allowlist-function vmnet_interface_set_event_callback\
  --allowlist-function vmnet_read\
  --allowlist-function vmnet_write\
  --allowlist-var vmnet_mtu_key\
  --allowlist-var vmnet_enable_checksum_offload_key\
  --allowlist-var vmnet_enable_tso_key\
  --allowlist-var vmnet_operation_mode_key\
  --allowlist-var vmnet_allocate_mac_address_key\
  --allowlist-var vmnet_mac_address_key\
  --allowlist-var vmnet_estimated_packets_available_key\
  --allowlist-var VMNET_HOST_MODE\
  --allowlist-var VMNET_SUCCESS\
  --allowlist-var VMNET_INTERFACE_PACKETS_AVAILABLE\
  --allowlist-function xpc_dictionary_create\
  --allowlist-function xpc_release\
  --allowlist-function xpc_uint64_create\
  --allowlist-function xpc_bool_create\
  --allowlist-function xpc_dictionary_get_string\
  --allowlist-function xpc_dictionary_get_uint64\
  --allowlist-function dispatch_get_global_queue\
  $INCLUDE_FILE \
  > src/l2gateway/iface/vmnet/sys.rs
rm "$INCLUDE_FILE"
