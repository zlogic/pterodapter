# Pterodapter

Pterodapter is a userspace VPN adapter that acts as an open/industry standard VPN server, and forwards traffic to 

No drivers to install or root access to create tun/utun devices.

At the moment, the plan is to build an L2TP (or Wireguard) adapter to connect to FortiVPN.

# Reference

## FortiVPN implementations

Used to study and re-implement the FortiVPN protocol:

* [openfortivpn](https://github.com/adrienverge/openfortivpn)
* [OpenConnect](https://www.infradead.org/openconnect/)

## WireGuard gateways

WireGuard's VPN client is available in the App Store, and supports split tunneling out of the box.

If L2TP doesn't work, this would be a good starting point;
in addition, this shows how to do L2/L3 conversion and emulate remote endpoints.

* [onetun](https://github.com/aramperes/onetun) - listen on a socket and redirect to a server through WireGuard
* [wgslirpy](https://github.com/vi/wgslirpy) - runs a WireGuard server and redirects to an external service
