# Generating certificates

Generate root CA private key

```shell
openssl ecparam -name prime256v1 -genkey -out vpn-root.key.pem
# openssl ec -in vpn-root.key.pem -pubout -out vpn-root.pub.pem
```

Generate root CA certificate:

```shell
SERVER_HOST=pterodapter.home
openssl req -new -x509 -key vpn-root.key.pem -out vpn-root.cert.pem -days 730 -subj "/C=NL/O=Pterodapter/CN=Pterodapter Root CA" \
  -addext "basicConstraints = critical, CA:TRUE" -addext "nameConstraints = critical, permitted;DNS:${SERVER_HOST}, permitted;email:${SERVER_HOST}"
```

rustls cannot verify email constraints; appending `;email:${SERVER_HOST}` to `nameConstraints` will fail validation.

To import root CA in Windows, rename `vpn-root.cert.pem` to `vpn-root.cert.crt` and import it into the machine's _Trusted Root Certification Authorities_.
Although importing a PFX bundle would import both the root and client certs into the right keystore.

To generate elliptic curve public keys, use `-newkey ec -pkeyopt ec_paramgen_curve:prime256v1`

## Server certificate

Generate server key

```shell
SERVER_HOST=pterodapter.home
openssl req -new -nodes -newkey ec:<(openssl ecparam -name prime256v1) -out vpn-server.csr.pem -keyout vpn-server.key.pem -days 730 -subj "/C=NL/O=Pterodapter/CN=${SERVER_HOST}"
openssl x509 -req -CAcreateserial -sha256 -CA vpn-root.cert.pem -CAkey vpn-root.key.pem -in vpn-server.csr.pem -out vpn-server.cert.pem -days 730 \
  -extensions v3_req -extfile <(echo "[ v3_req ]
subjectAltName = DNS:${SERVER_HOST}
extendedKeyUsage = serverAuth, 1.3.6.1.5.5.8.2.2
basicConstraints = critical, CA:FALSE")
rm vpn-server.csr.pem
```

## Client certificates

Generate client key

```shell
SERVER_HOST=pterodapter.home
USER_EMAIL="user@${SERVER_HOST}"
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) -out vpn-client.csr.pem -keyout vpn-client.key.pem -days 730 -subj "/C=NL/O=Pterodapter Client/CN=${USER_EMAIL}"
openssl x509 -req -CAcreateserial -sha256 -CA vpn-root.cert.pem -CAkey vpn-root.key.pem -in vpn-client.csr.pem -out vpn-client.cert.pem -days 730 \
  -extensions v3_req -extfile <(echo "[ v3_req ]
subjectAltName = email:${USER_EMAIL}
extendedKeyUsage = clientAuth
keyUsage = digitalSignature
basicConstraints = critical, CA:FALSE")
rm vpn-client.csr.pem
```

### Windows

Export certificate for Windows:

```shell
openssl pkcs12 -export -out vpn-client.pfx -inkey vpn-client.key.pem -in vpn-client.cert.pem -certfile vpn-root.cert.pem
```

Import into the _Local Machine_ store, and let Windows automatically select certificate store.

For more details on configuring Windows, check the [StrongSwan documentation](https://docs.strongswan.org/docs/5.9/interop/windowsMachineConf.html).

To be able to use ECDSA certs, run the following command (replace `<name>` with the VPN connection name):

```
Set-VpnConnectionIPsecConfiguration -ConnectionName <name> -CipherTransformConstants GCMAES256 -EncryptionMethod GCMAES256 -IntegrityCheckMethod SHA256 -DHGroup ECP256 -AuthenticationTransformConstants GCMAES256 -PfsGroup None
```

### macOS

Export certificate for macOS:

```shell
openssl pkcs12 -export -legacy -out vpn-client.pfx -inkey vpn-client.key.pem -in vpn-client.cert.pem -certfile vpn-root.cert.pem
```

When importing the certificate, use the Keychain access app, and select the System keychain as the destination.

To grant access, go to _My Certificates_ and grant `/System/Library/Frameworks/NetworkExtension.framework/Plugins/NEIKEv2Provider.appex/Contents/MacOS/NEIKEv2Provider.appex` access to the private cert's private key.
