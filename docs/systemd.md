# Systemd unit file

Create a systemd unit file:

```shell
cat <<EOF > ~/.config/systemd/user/pterodapter.service
[Unit]
Description=Pterodapter

[Service]
Type=exec
WorkingDirectory=/var/home/core/pterodapter
ExecStart=/var/home/core/pterodapter/pterodapter --log-level=trace --listen-ip=:: --id-hostname=schmetterling.home\\
    --fortivpn=fortivpn.example.com:443\\
    --cacert=vpn-root.cert.pem --cert=vpn-server.cert.pem --key=vpn-server.key.pem\\
    --tunnel-domain=gitlab.example.com --tunnel-domain=jenkins.example.com\\
    ikev2
KillSignal=SIGINT
KillMode=process
Restart=on-failure

[Install]
WantedBy=default.target
EOF
```

and start it without logging in:

```shell
sudo loginctl enable-linger $USER
```

Monitor logs by running:

```shell
journalctl -f --user -xeu pterodapter.service
```
