# Pterodapter

![Build status](https://github.com/zlogic/pterodapter/actions/workflows/cargo-build.yml/badge.svg)

Pterodapter is a userspace SOCKS5-to-FortiVPN adapter that acts as an open standard SOCKS5 proxy server, and forwards traffic to a FortiVPN network.

No drivers to install or root access to create tun/utun devices.

As it can be used with [PAC files](https://en.wikipedia.org/wiki/Proxy_auto-config), hostname-based routing might be a lot easier.
(especially if the IP address keeps changing, and routing tables keep getting out of date).

[smoltcp](https://github.com/smoltcp-rs/smoltcp) emulates L3 physical hardware and allows conversion of L5 (SOCKS5) traffic into L3 packets.

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
