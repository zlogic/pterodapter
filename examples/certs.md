# Generating certificates

Generate root CA private key

```shell
openssl ecparam -name prime256v1 -genkey -out vpn-root.key.pem
# openssl ec -in vpn-root.key.pem -pubout -out vpn-root.pub.pem
```

Generate root CA certificate

```shell
SERVER_HOST=pterodapter.home
openssl req -new -x509 -key vpn-root.key.pem -out vpn-root.cert.pem -days 730 -subj "/C=NL/O=Pterodapter/CN=Pterodapter Root CA" \
  -addext "basicConstraints = critical, CA:TRUE" -addext "nameConstraints = critical, permitted;DNS:${SERVER_HOST}, permitted;email:${SERVER_HOST}"
```

To import root CA in Windows, rename `vpn-root.cert.pem` to `vpn-root.cert.crt` and import it into the machine's _Trusted Root Certification Authorities_.
Although importing a PFX bundle would import both the root and client certs into the right keystore.

To generate elliptic curve public keys, use `-newkey ec -pkeyopt ec_paramgen_curve:prime256v1`

## Server certificate

Generate server key

```shell
SERVER_HOST=pterodapter.home
openssl ecparam -name prime256v1 -genkey -out vpn-server.key.pem
openssl req -new -x509 -CA vpn-root.cert.pem -CAkey vpn-root.key.pem -out vpn-server.cert.pem -keyout vpn-server.key.pem -days 730 -subj "/C=NL/O=Pterodapter/CN=${SERVER_HOST}" \
  -addext "subjectAltName = DNS:${SERVER_HOST}" -addext "extendedKeyUsage = serverAuth, 1.3.6.1.5.5.8.2.2"
```

## Client certificates

Generate client key

```shell
SERVER_HOST=pterodapter.home
USERNAME="user@${SERVER_HOST}"
openssl ecparam -name prime256v1 -genkey -out vpn-client.key.pem
openssl req -new -x509 -CA vpn-root.cert.pem -CAkey vpn-root.key.pem -out vpn-client.cert.pem -keyout vpn-client.key.pem -days 730 -subj "/C=NL/O=Pterodapter Client/CN=${USERNAME}" \
  -addext "subjectAltName = email:${USERNAME}" -addext "extendedKeyUsage = clientAuth" -addext "keyUsage = digitalSignature" -addext "basicConstraints = critical, CA:FALSE"
```

### Windows

Export certificate for Windows:

```shell
openssl pkcs12 -export -out vpn-client.pfx -inkey vpn-client.key.pem -in vpn-client.cert.pem -certfile vpn-root.cert.pem
```

Import into the _Local Machine_ store, and let Windows automatically select certificate store.

For more details on configuring Windows, check the [StrongSwan documentation](https://docs.strongswan.org/docs/5.9/interop/windowsMachineConf.html).

### macOS

Export certificate for macOS:

```shell
openssl pkcs12 -export -legacy -out vpn-client.pfx -inkey vpn-client.key.pem -in vpn-client.cert.pem -certfile vpn-root.cert.pem
```

When importing the certificate, use the Keychain access app, and select the System keychain as the destination.
