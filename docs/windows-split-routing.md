# Windows split routing

macOS will use IKEv2 traffic selectors and the `INTERNAL_DNS_DOMAIN` IKEv2 attribute to automatically set up network routes and use the VPN DNS servers for all domains specified with `--dns64-tunnel-suffix`.

Windows instead relies on heuristics (internal IP address and network), [DHCP](https://docs.strongswan.org/docs/latest/interop/windowsClients.html#_split_routing_since_windows_10), or on manually provided routes.

## Configuring split routing

To enable split routing for a connection, run the following command in PowerShell (replace `<name>` with the VPN connection name):

```powershell
Set-VpnConnection -ConnectionName <name> -SplitTunneling $true
```

Then, add a route for the subnect specified in `--nat64-prefix` (replace `<name>` with the VPN connection name):

```powershell
Add-VpnConnectionRoute -ConnectionName <name> -DestinationPrefix "64:ff9b::/96" -RouteMetric 1
```

`RouteMetric` ensures that this connection and its DNS64 has the highest possible priority.

This command also accepts IPv4 addresses and can be combined with the `--tunnel-domain` option.
When the VPN connection disconnects, these routes will be removed automatically.

## Enforcing a specific DNS server

To always use the VPN DNS for subdomains of a server, use the `Add-DnsClientNrptRule` PowerShell command:

```powershell
Add-DnsClientNrptRule -Namespace ".example.com" -NameServers "64:ff9b::808:808"
```

⚠️ This will use the specified DNS server even when the VPN client is disconnected.
In most cases, this is not necessary, as `RouteMetric 1` ensures that all DNS requests are routed through the DNS64 translator.

## Validating DNS configuration

`nslookup` on Windows doesn't use route metrics and might not use the VPN DNS.

To test that DNS works correctly, use the `Resolve-DnsName` PowerShell command.

