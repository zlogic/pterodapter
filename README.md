# pterodapter

![Build status](https://github.com/zlogic/pterodapter/actions/workflows/cargo-build.yml/badge.svg)

<img src="logo.png" alt="Logo" style="width:32px;height:32px;">

pterodapter is a userspace IKEv2-to-FortiVPN adapter that acts as an L3 IKEv2 VPN server (a subset of [RFC 7296](https://datatracker.ietf.org/doc/html/rfc7296) is implemented) and forwards traffic to a FortiVPN network.

![Connection diagram](diagram.svg)

Previous versions also supported a proxy mode, which was deprecated once IKEv2 improved support for DNS-based split routing.

The last version supporting proxy mode is [0.5.0](https://github.com/zlogic/pterodapter/tree/0.5.0).

## IKEv2 VPN mode

Root permissions are not required, but unfortunately most IKEv2 clients can only use standard ports 500 and 4500.
Listening on port 500 requires elevated permissions or port-forwarding; the IKEv2 server needs to run externally to prevent port conflicts.

To avoid granting root permissions, the following command grants permissions to listen on ports < 1024 without granting full root access:

```shell
sudo setcap CAP_NET_BIND_SERVICE=+eip pterodapter
```

# How to use it

Run pterodapter with the following arguments:

```shell
pterotapter [--log-level=<level>] [--listen-ip=<ip-address>] [--ike-port=<port>] [--nat-port=<port>] --destination=<hostport> [--tunnel-domain=<domain>] [--nat64-prefix=<ip6prefix>] [--dns64-tunnel-suffix=<domain>] [--id-hostname=<hostname>] --cacert=<filename> --cert=<filename> --key=<filename> ikev2
```

`--log-level=<level>` is an optional argument to specify the log level, for example `--log-level=debug`.

`--listen-ip=<ip-address>` is an optional argument to specify the IKEv2 listen IP address, for example `--listen-ip=127.0.0.1`. If not specified, will use `::` as the listen address (all IPv4 and IPv6 addresses). Multiple addresses can be specified.

`--ike-port=<port>` is an optional argument to specify the IKEv2 listen port, for example `--ike-port=9500`. If not specified, will use port 500 (the default IKEv2 port).

`--nat-port=<port>` is an optional argument to specify the NAT port for IKEv2 and ESP, for example `--nat-port=9501`. If not specified, will use port 4500 (the default IKEv2 and ESP NAT port).

`--destination=<hostport>` specifies the FortiVPN connection address, for example `--destination=fortivpn.example.com:443`.

`--tunnel-domain=<domain>` specifies an optional argument indicating that only `<domain>` should be sent through the VPN, and all other domains should use a direct connection. To specify multiple domains, add a `--tunnel-domain` argument for each one; if no `--tunnel-domain` arguments are specified, all traffic will be sent through the VPN.
This is implemented using IKEv2 traffic selectors and works with no extra configuration on macOS; Windows needs routes [to be added manually](docs/windows-split-routing.md).
To ensure that dynamic IPs are handled correctly, pterodapter will send updated routes (IKEv2 Traffic Selectors) when the client rekeys the session.
This option only affects IPv4 traffic. For NAT64 split tunnel routing, use the `--dns64-tunnel-suffix` argument.

`--nat64-prefix=<ip6prefix>` specifies an optional argument indicating that [NAT64](https://en.wikipedia.org/wiki/NAT64) mode should be enabled, for example `--nat64-prefix=64:ff9b::` will remap IPv4 addresses to a /96 IPv6 subnet matching `64:ff9b::`-`64:ff9b::ffff:ffff`.
In NAT64 mode, pterodapter will intercept DNS responses and remap external IPv4 addresses to IPv6 addresses in the specified subnet.
This is done only for domains matching a suffix listed in `--tunnel-domain`.
The IKEv2 client will use IPv6 traffic, which is translated into IPv4 and sent to VPN, based on the SIIT algorithm documented in [RFC 7915](https://datatracker.ietf.org/doc/html/rfc7915).
This approach simplifies the routing table (IKEv2 Traffic Selector) to use only one network or traffic selector; it also allows to use domain suffixes and handle DNS updates without reconnecting the client.
Inspired by ideas from [Microsoft DirectAccess](https://en.wikipedia.org/wiki/DirectAccess).

`--dns64-tunnel-suffix=<domain>` specifies an optional argument indicating that `<domain>` and its subdomains should be sent through the VPN using NAT64 (DNS64).
To specify multiple domains, add a `--dns64-tunnel-suffix` argument for each one.
If no `--dns64-tunnel-suffix` arguments are specified, DNS64 won't be used, but will still remain available - for example, to be used with a custom DNS64 server.

`--destination=<hostport>` specifies the hostname to send to the client when performing a client handshake. If not specified, will use `pterodapter` as the hostname. Windows refuses to connect if the hostname doesn't match connection settings; macOS prints a warning in the Console.

`--cacert=<filename>` specifies the path to a root CA PEM file, required for two-way authentication.

`--cert=<filename>` specifies the path to the server's public cert PEM file, required for two-way authentication.

`--key=<filename>` specifies the path to the server's private key PEM file (matching the public cert specified in `--cert`), required for two-way authentication.

For example:

```shell
./pterodapter --log-level=trace \
    --listen-ip=127.0.0.1 \
    --destination=fortivpn.example.com:443 \
    --tunnel-domain=gitlab.example.com \
    --tunnel-domain=registry.example.com \
    --nat64-prefix=64:ff9b:: \
    --dns64-tunnel-suffix=example.com \
    --id-hostname=pterodapter.home \
    --cacert=vpn-root.cert.pem \
    --cert=vpn-server.cert.pem \
    --key=vpn-server.key.pem \
    ikev2
```

For more information how to generate certs and configure clients, see the [certs.md](docs/certs.md) document.

For information how to run pterodapter as a systemd unit, see the [systemd.md](docs/systemd.md) document.

For information how to enable split routing in Windows, see the [windows-split-routing.md](docs/windows-split-routing.md) document.

## Running on the same host

IKEv2 relies on fixed port numbers (500 and 4500) and most implementations (macOS and Windows built-in VPN clients) don't allow to specify a custom port number.
Additionally, IKEv2 uses fixed ports on the client side as well.

This means running pterodapter on the same host as the client could cause issues.

* For Windows, run pterodapter in WSL with NAT networking mode (mirrored networking might work but is untested).
* For macOS, [create a virtual IP](docs/macos-pf.md) in built-in packet filter .

# Reference

## FortiVPN implementations

Used to study and re-implement the FortiVPN protocol:

* [openfortivpn](https://github.com/adrienverge/openfortivpn)
* [OpenConnect](https://www.infradead.org/openconnect/)

The idea of using a proxy (to run as non-root) was originally suggested in [the OpenConnect documentation](https://www.infradead.org/openconnect/nonroot.html).

## WireGuard gateways

WireGuard's VPN client is available in the App Store, and supports split tunneling out of the box.
Could be a possible alternative to proxies - keep split tunneling, but avoid conversion between OSI layers.

These examples show how to do L2/L3 conversion and emulate remote endpoints.

* [onetun](https://github.com/aramperes/onetun) - listen on a socket and redirect to a server through WireGuard
* [wgslirpy](https://github.com/vi/wgslirpy) - runs a WireGuard server and redirects to an external service
