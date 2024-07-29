# Pterodapter

![Build status](https://github.com/zlogic/pterodapter/actions/workflows/cargo-build.yml/badge.svg)

<img src="logo.png" alt="Logo" style="width:32px;height:32px;">

Pterodapter is a userspace Proxy-to-FortiVPN adapter that acts as an open standard SOCKS5/HTTP/CONNECT proxy server, and forwards traffic to a FortiVPN network.

No drivers to install or root access to create tun/utun devices.

As it can be used with [PAC files](https://en.wikipedia.org/wiki/Proxy_auto-config), hostname-based routing might be a lot easier.
(especially if the IP address keeps changing, and routing tables keep getting out of date).

[smoltcp](https://github.com/smoltcp-rs/smoltcp) emulates L3 physical hardware and allows conversion of L5 (SOCKS5/HTTP/CONNECT proxy) traffic into L3 packets.


# How to use it

Build/download a copy, and run it using the following options:

```shell
pterotapter [--log-level=<level>] [--listen-address=<hostport>] --destination=<hostport> [--pac-file=<path>] [--tunnel-domain=<suffix>] proxy
```

`--log-level=<level>` is an optional argument to specify the log level, for example `--log-level=debug`.

`--listen-address=<hostport>` is an optional argument to specify the proxy listen address, for example `--listen-address=127.0.0.1:3128`. If not specified, will use `:::5328` as the listen address (all IPv4 and IPv6 addresses, port 5328).

`--destination=<hostport>` specifies the FortiVPN connection address, for example `--destination=fortivpn.example.com:443`.

`--pac-file=<path>` specifies the optional filename/path for a [PAC file](https://en.wikipedia.org/wiki/Proxy_auto-config). This pac file will be available at the listen address' `/proxy.pac` path, and can be used to self-host a PAC file for browsers/clients that support it.

`--tunnel-domain=<suffix>` specifies an optional argument indicating that only domains matching `<suffix>` should be sent through the VPN, and all other domains should use a direct connection. Multiple domains can be specified; if no `--tunnel-domain` arguments are specified, all traffic will be sent through the VPN.

For example:

```shell
./pterodapter --log-level=trace \
    --listen-address=127.0.0.1:3128 \
    --destination=fortivpn.example.com:443 \
    --pac-file=custom.pac \
    --tunnel-domain=gitlab.example.com \
    --tunnel-domain=registry.example.com \
    --tunnel-domain=-ci.example.com \
    proxy
```

Example contents of a PAC file:

```javascript
function FindProxyForURL(url, host) {
    // Gitlab
    if (shExpMatch(host, "gitlab.example.com"))
        return "SOCKS 127.0.0.1:3128";

    // Registry
    if (shExpMatch(host, "*.registry.example.com"))
        return "PROXY 127.0.0.1:3128";

    // Direct connection by default
    return "DIRECT";
}
```

## How to set up a client

Configure your browser to use a PAC file, for example:

```shell
networksetup -setautoproxyurl "Wi-Fi" "http://localhost:5328/proxy.pac"
```

To enable SSH proxying, add this to `~/.ssh/config` (specify the path to `git-proxy-command.sh`):

```
Host ssh.gitlab.example.com
    ProxyCommand nc -x localhost:5328 %h %p
```

To use most CLI tools, set the following environment variables:

```shell
export HTTP_PROXY=http://localhost:5328
export HTTPS_PROXY=http://localhost:5328
export NO_PROXY=127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

For containers running in Podman Machine, use `host.containers.internal` instead of `localhost`.

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
