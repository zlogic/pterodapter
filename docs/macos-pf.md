# How to run pterodapter on localhost

IKEv2 relies on fixed port numbers (500 and 4500) and most implementations (macOS and Windows built-in VPN clients) don't allow to specify a custom port number.
Additionally, IKEv2 uses fixed ports on the client side as well.

This means that running on localhost (127.0.0.1 or ::1) will connect from `127.0.0.1:500` to `127.0.0.1:500`, and fail if pterodapter is already using port 500.
Using another localhost destination IP address (e.g. 127.0.0.2, 127.0.1.1 or ::1) will also change the source IP address - it's not possible to connect from 127.0.0.1 to 127.0.0.2.
The macOS IKEv2 client also seems to prefer real network cards (en0), even with `route add` or `networksetup -setadditionalroutes` route traffic through lo0.

The solution is using the built-in [pf](https://www.openbsd.org/faq/pf/index.html) filter to set up a fake IP address (e.g. fd00::40, an IPv6 unique local address) and redirect all packets to a custom port used by pterodapter.

This document explains how to set up a rule so that `[fd00::40]:500` is redirected to `[::1]:9500`, and `[fd00::40]:4500` is redirected to `[::1]:9501`; this way, a local copy of pterodapter will look like it's running at `fd00::40`.


## Simple PF rule

Run pterodapter on ports 9500 + 9501 - and specify fd00::40 as the destination host.

```shell
cat << EOF | sudo pfctl -e -f -
rdr pass proto udp from any to fd00::40 port 500 tag MAC_TO_VPN -> ::1 port 9500
rdr pass proto udp from any to fd00::40 port 4500 tag MAC_TO_VPN -> ::1 port 9501
pass out quick on en0 route-to lo0 inet6 proto udp from any to fd00::40 port {500, 4500} tag MAC_TO_VPN
EOF
```

Technically, this is not needed, but might help:

```shell
sudo sysctl net.inet.ip.forwarding=1
```

## PF anchor

Instead of completely replacing all pf rules, add a custom anchor (using the predefined `com.apple` prefix):

Enable the firewall:

```shell
sudo pfctl -ef /etc/pf.conf
```

and add an achor:

```shell
cat << EOF | sudo pfctl -a com.apple/pterodapter -f -
rdr pass proto udp from any to fd00::40 port 500 tag MAC_TO_VPN -> ::1 port 9500
rdr pass proto udp from any to fd00::40 port 4500 tag MAC_TO_VPN -> ::1 port 9501
pass out quick on en0 route-to lo0 inet6 proto udp from any to fd00::40 port {500, 4500} tag MAC_TO_VPN
EOF
```

## PF tips

Check status with

```shell
sudo pfctl -s all
```

Show all anchors with

```shell
sudo pfctl -vsA
```

Reset to default rules with

```shell
sudo pfctl -ef /etc/pf.conf
```

Disable packet filter with

```shell
sudo pfctl -d
```
# Other ideas

* Automatically load PF rules using [launchd](https://apple.stackexchange.com/a/429972)
* VM-based virtual net using [socket_vmnet](https://lima-vm.io/docs/config/network/), requires root permissions
* Run lightweight VM using [vfkit](https://github.com/crc-org/vfkit)
* Reuse parts of [SimpleTunnel](https://developer.apple.com/library/archive/samplecode/SimpleTunnel/Introduction/Intro.html) example project

