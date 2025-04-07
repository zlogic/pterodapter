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

rustls cannot verify email constraints; appending `, permitted;email:${SERVER_HOST}` to `nameConstraints` will fail validation.

To import root CA in Windows, rename `vpn-root.cert.pem` to `vpn-root.cert.crt` and import it into the machine's _Trusted Root Certification Authorities_.
Although importing a PFX bundle would import both the root and client certs into the right keystore.

To generate elliptic curve public keys, use `-newkey ec -pkeyopt ec_paramgen_curve:prime256v1`

## Server certificate

Generate server key

```shell
SERVER_HOST=pterodapter.home
openssl req -new -nodes -newkey ec:<(openssl ecparam -name prime256v1) -out vpn-server.csr.pem -keyout vpn-server.key.pem -subj "/C=NL/O=Pterodapter/CN=${SERVER_HOST}"
openssl x509 -req -CAcreateserial -sha256 -CA vpn-root.cert.pem -CAkey vpn-root.key.pem -in vpn-server.csr.pem -out vpn-server.cert.pem -days 730 \
  -extensions v3_req -extfile <(echo "[ v3_req ]
subjectAltName = DNS:${SERVER_HOST}
extendedKeyUsage = serverAuth, 1.3.6.1.5.5.8.2.2
basicConstraints = critical, CA:FALSE")
rm vpn-server.csr.pem
```

⚠️ Windows seems to fail TLS certificate validation if the VPN destination is an IP address and not a FQDN.
StrongSwan suggests that this might work if the IP address is used as a `subjectAltName`, but these certificates will be rejected by rustls-webpki.

If the VPN server doesn't have a hostname (e.g. is running on WSL), use a wildcard DNS service like `nip.io`, `sslip.io` or a static entry in `C:\Windows\System32\drivers\etc\hosts`.

## Client certificates

Generate client key

```shell
SERVER_HOST=pterodapter.home
USER_EMAIL="user@${SERVER_HOST}"
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) -out vpn-client.csr.pem -keyout vpn-client.key.pem -subj "/C=NL/O=Pterodapter Client/CN=${USER_EMAIL}"
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

```powershell
Set-VpnConnectionIPsecConfiguration -ConnectionName <name> -CipherTransformConstants GCMAES256 -EncryptionMethod GCMAES256 -IntegrityCheckMethod SHA256 -DHGroup ECP256 -AuthenticationTransformConstants GCMAES256 -PfsGroup ECP256
```

### macOS

Using ECDSA signatures in macOS requires configuring VPN through a configuration profile.

For more information, see the [StrongSwan documentation](https://docs.strongswan.org/docs/5.9/interop/appleIkev2Profile.html).

Generate a `vpn.mobileconfig` file based on the example below, and open it in macOS; [Apple Configurator](https://apps.apple.com/app/id1037126344) can also generate `.mobileconfig` files using a GUI.

```xml
<?xml version="1.0" encoding="$UTF_8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <!-- Use uuidgen to generate unique PayloadUUID values -->
  <key>PayloadUUID</key>
  <string>BA1F6065-97BE-45D0-B6AD-B7B0EBAAA29C</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadIdentifier</key>
  <string>org.pterodapter.home.vpn1</string>
  <key>PayloadDisplayName</key>
  <string>VPN Tunnel Config</string>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadIdentifier</key>
      <string>org.pterodapter.home.vpn1.conf1</string>
      <key>PayloadUUID</key>
      <string>64B6E573-DC00-4B74-AFCC-2A12379530DC</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>UserDefinedName</key>
      <string>VPN Tunnel</string>
      <key>VPNType</key>
      <string>IKEv2</string>
      <key>IKEv2</key>
      <dict>
        <key>RemoteAddress</key>
        <string>pterodapter.home</string>
        <key>RemoteIdentifier</key>
        <string>pterodapter.home</string>
        <key>LocalIdentifier</key>
        <string>macos@pterodapter.home</string>
        <key>ServerCertificateCommonName</key>
        <string>pterodapter.home</string>
        <key>AuthenticationMethod</key>
        <string>Certificate</string>
        <key>ExtendedAuthEnabled</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <integer>1</integer>
        <key>CertificateType</key>
        <string>ECDSA256</string>
        <key>PayloadCertificateUUID</key>
        <!-- This must match the PayloadUUID of the com.apple.security.pkcs12 certificate below -->
        <string>19619023-6EB8-47FB-A942-6A15976AD51E</string>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>DiffieHellmanGroup</key>
          <integer>19</integer>
        </dict>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>DiffieHellmanGroup</key>
          <integer>19</integer>
        </dict>
      </dict>
    </dict>
    <dict>
      <key>PayloadIdentifier</key>
      <string>org.pterodapter.home.vpn1.client</string>
      <key>PayloadUUID</key>
      <string>19619023-6EB8-47FB-A942-6A15976AD51E</string>
      <key>PayloadType</key>
      <string>com.apple.security.pkcs12</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <!--
      <key>Password</key>
      <string></string>
      -->
      <key>PayloadContent</key>
      <!--
      openssl pkcs12 -export -legacy -inkey vpn-client.key.pem -in vpn-client.cert.pem -certfile vpn-root.cert.pem | base64
      -->
      <data>
MIIG...
      </data>
    </dict>
    <dict>
      <key>PayloadIdentifier</key>
      <string>org.pterodapter.home.ca</string>
      <key>PayloadUUID</key>
      <string>C8D26DC0-72AF-4625-91AD-97637FA03EF7</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadContent</key>
      <!-- PEM contents without the headers -->
      <data>
MIIB...
      </data>
    </dict>
  </array>
</dict>
</plist>
```
