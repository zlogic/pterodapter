use std::{error, fmt, sync::Arc};

use aws_lc_rs::{digest, signature};
use base64::engine::{Engine as _, general_purpose};
use log::warn;
use tokio_rustls::rustls::{self, pki_types};
use x509_cert::{der::Decode as _, ext::pkix};

use crate::logger::fmt_slice_hex;

use super::message;

pub struct PkiProcessing {
    server_id: Option<Vec<u8>>,
    client_validation: Option<ClientValidation>,
    server_identity: Option<ServerIdentity>,
}

impl PkiProcessing {
    pub fn new(
        hostname: Option<&str>,
        root_ca: Option<&str>,
        server_cert: Option<(&str, &str)>,
    ) -> Result<PkiProcessing, CertError> {
        let client_validation = if let Some(root_ca) = root_ca {
            Some(ClientValidation::new(root_ca)?)
        } else {
            None
        };
        let server_identity = if let Some((public_cert, private_key)) = server_cert {
            Some(ServerIdentity::new(public_cert, private_key)?)
        } else {
            None
        };

        if let (Some(client_validation), Some(server_identity)) =
            (&client_validation, &server_identity)
        {
            let server_cert_der =
                pki_types::CertificateDer::from_slice(server_identity.public_cert_der.as_slice());
            client_validation
                .verify_server_cert(&server_cert_der)
                .map_err(|err| {
                    warn!("Failed to validate server certificate: {err}");
                    err
                })?;
        };

        let server_id = if let Some(hostname) = hostname {
            let hostname = hostname.as_bytes();
            let mut server_id = vec![0u8; 4 + hostname.len()];
            server_id[0] = message::IdentificationType::ID_FQDN.type_id();
            server_id[4..].copy_from_slice(hostname);
            Some(server_id)
        } else {
            None
        };
        Ok(PkiProcessing {
            server_id,
            client_validation,
            server_identity,
        })
    }

    pub fn root_ca_request(&self) -> Option<&[u8]> {
        if let Some(client_validation) = &self.client_validation {
            Some(client_validation.root_ca_request())
        } else {
            None
        }
    }

    pub fn default_server_cert(&self) -> Option<&[u8]> {
        if let Some(server_identity) = &self.server_identity {
            Some(server_identity.public_cert_der())
        } else {
            None
        }
    }

    pub fn server_cert(&self, certificate_request: &[u8]) -> Option<&[u8]> {
        if let Some(client_validation) = &self.client_validation {
            if !certificate_request
                .chunks(20)
                .any(|ca| client_validation.root_ca_request == ca)
            {
                return None;
            }
        }

        self.default_server_cert()
    }

    pub fn server_id(&self) -> Option<&[u8]> {
        self.server_id.as_deref()
    }

    pub fn verify_client_cert(
        &self,
        client_cert_der: &[u8],
    ) -> Result<ClientCertificate, CertError> {
        let client_cert = pki_types::CertificateDer::from(client_cert_der);
        if let Some(client_validation) = &self.client_validation {
            client_validation.verify_client_cert(&client_cert)?;
        }

        let client_cert = x509_cert::Certificate::from_der(client_cert_der)?;
        let san = client_cert
            .tbs_certificate
            .filter::<pkix::SubjectAltName>()
            .filter_map(|res| match res {
                Ok((_, pkix::SubjectAltName(subject_alternative_name))) => subject_alternative_name
                    .iter()
                    .filter_map(|general_name| match general_name {
                        pkix::name::GeneralName::Rfc822Name(name) => {
                            Some(name.as_str().to_string())
                        }
                        pkix::name::GeneralName::DnsName(name) => Some(name.as_str().to_string()),
                        pkix::name::GeneralName::UniformResourceIdentifier(name) => {
                            Some(name.as_str().to_string())
                        }
                        _ => None,
                    })
                    .next(),
                Err(err) => {
                    warn!("Failed to parse client cert Subject Alternative Names: {err}");
                    None
                }
            })
            .next();
        let subject_cn = client_cert
            .tbs_certificate
            .subject
            .0
            .iter()
            .filter_map(|entry| format!("{entry}").into())
            .next();
        let subject = if let Some(san) = san {
            san
        } else if let Some(subject_cn) = subject_cn {
            subject_cn
        } else {
            client_cert.tbs_certificate.subject.to_string()
        };
        let serial = client_cert
            .tbs_certificate
            .serial_number
            .as_bytes()
            .to_vec();
        let public_key = client_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();

        Ok(ClientCertificate {
            public_key,
            subject,
            serial,
        })
    }

    pub fn sign_auth(
        &self,
        format: SignatureFormat,
        msg: &[u8],
        dest: &mut [u8],
    ) -> Result<usize, CertError> {
        if let Some(server_identity) = &self.server_identity {
            server_identity.sign_message(format, msg, dest)
        } else {
            Err("No server identity is configured".into())
        }
    }
}

pub struct ClientCertificate {
    public_key: Vec<u8>,
    subject: String,
    serial: Vec<u8>,
}

const ASN1_IDENTIFIDER_ECDSA_WITH_SHA256: [u8; 12] = [
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

impl ClientCertificate {
    pub fn subject(&self) -> &str {
        self.subject.as_str()
    }

    pub fn serial(&self) -> &[u8] {
        self.serial.as_slice()
    }

    pub fn verify_signature(
        &self,
        format: SignatureFormat,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), CertError> {
        let (algorithm, signature) = match format {
            SignatureFormat::Default => (&signature::ECDSA_P256_SHA256_FIXED, signature),
            SignatureFormat::AdditionalParameters => {
                if signature.is_empty() {
                    return Err("No ASN.1 length in Digital Signature".into());
                }
                let asn1_length = signature[0] as usize;
                if signature.len() < 1 + asn1_length {
                    return Err("Digital Signature ASN.1 AlgorithmIdentifier overflow".into());
                }
                let signature_oid = &signature[1..1 + asn1_length];
                if signature_oid != ASN1_IDENTIFIDER_ECDSA_WITH_SHA256 {
                    warn!(
                        "Unsupported ASN.1 AlgorithmIdentifier {}",
                        fmt_slice_hex(signature_oid)
                    );
                    return Err("Unsupported ASN.1 AlgorithmIdentifier".into());
                }
                (
                    &signature::ECDSA_P256_SHA256_ASN1,
                    &signature[1 + asn1_length..],
                )
            }
        };
        let verifying_key = signature::UnparsedPublicKey::new(algorithm, &self.public_key);
        verifying_key
            .verify(msg, signature)
            .map_err(|_| "Signature verification failed")?;
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignatureFormat {
    Default,
    AdditionalParameters,
}

struct ClientValidation {
    root_ca_request: [u8; 20],
    verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    root_certs: Arc<rustls::RootCertStore>,
}

impl ClientValidation {
    pub fn new(root_ca_pem: &str) -> Result<ClientValidation, CertError> {
        let root_ca_der = pem_to_der(root_ca_pem, &PEM_SECTION_CERTIFICATE)?;
        let root_ca = pki_types::CertificateDer::from(root_ca_der.as_slice());

        let mut root_ca_request = [0u8; 20];
        let root_ca_hash = digest::digest(
            &digest::SHA1_FOR_LEGACY_USE_ONLY,
            webpki::EndEntityCert::try_from(&root_ca)?
                .subject_public_key_info()
                .as_ref(),
        );
        root_ca_request.copy_from_slice(root_ca_hash.as_ref());

        let mut root_certs = rustls::RootCertStore::empty();
        root_certs.add(root_ca)?;
        let root_certs = Arc::new(root_certs);
        let verifier = rustls::server::WebPkiClientVerifier::builder(root_certs.clone()).build()?;

        Ok(ClientValidation {
            root_ca_request,
            verifier,
            root_certs,
        })
    }

    fn root_ca_request(&self) -> &[u8] {
        &self.root_ca_request
    }

    fn verify_client_cert(&self, client_cert: &pki_types::CertificateDer) -> Result<(), CertError> {
        self.verifier
            .verify_client_cert(client_cert, &[], pki_types::UnixTime::now())?;
        Ok(())
    }

    fn verify_server_cert(&self, server_cert: &pki_types::CertificateDer) -> Result<(), CertError> {
        let server_cert = webpki::EndEntityCert::try_from(server_cert)?;
        server_cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            self.root_certs.roots.as_slice(),
            &[],
            pki_types::UnixTime::now(),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )?;
        Ok(())
    }
}

struct ServerIdentity {
    public_cert_der: Vec<u8>,
    key_pair_fixed: signature::EcdsaKeyPair,
    key_pair_asn1: signature::EcdsaKeyPair,
}

impl ServerIdentity {
    fn new(public_cert_pem: &str, private_key_pem: &str) -> Result<ServerIdentity, CertError> {
        let public_cert_der = pem_to_der(public_cert_pem, &PEM_SECTION_CERTIFICATE)?;

        let private_key_der = pem_to_der(private_key_pem, &PEM_SECTION_PRIVATE_KEY)?;
        let key_pair_fixed = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &private_key_der,
        )
        .map_err(|_| "Failed to parse ECDSA private key")?;
        let key_pair_asn1 = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &private_key_der,
        )
        .map_err(|_| "Failed to parse ECDSA private key")?;
        Ok(ServerIdentity {
            public_cert_der,
            key_pair_fixed,
            key_pair_asn1,
        })
    }

    fn public_cert_der(&self) -> &[u8] {
        &self.public_cert_der
    }

    fn sign_message(
        &self,
        format: SignatureFormat,
        msg: &[u8],
        dest: &mut [u8],
    ) -> Result<usize, CertError> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let key_pair = match format {
            SignatureFormat::Default => &self.key_pair_fixed,
            SignatureFormat::AdditionalParameters => &self.key_pair_asn1,
        };
        let signature = key_pair
            .sign(&rng, msg)
            .map_err(|_| "Failed to sign message")?;
        let signature_length = signature.as_ref().len();
        match format {
            SignatureFormat::Default => {
                dest[..signature_length].copy_from_slice(signature.as_ref());
                Ok(signature_length)
            }
            SignatureFormat::AdditionalParameters => {
                let oid_length = ASN1_IDENTIFIDER_ECDSA_WITH_SHA256.len();
                dest[0] = oid_length as u8;
                dest[1..1 + oid_length].copy_from_slice(&ASN1_IDENTIFIDER_ECDSA_WITH_SHA256);
                dest[1 + oid_length..1 + oid_length + signature_length]
                    .copy_from_slice(signature.as_ref());
                Ok(1 + oid_length + signature_length)
            }
        }
    }
}

struct PemSection {
    begin: &'static str,
    end: &'static str,
}

const PEM_SECTION_CERTIFICATE: PemSection = PemSection {
    begin: "-----BEGIN CERTIFICATE-----",
    end: "-----END CERTIFICATE-----",
};
const PEM_SECTION_PRIVATE_KEY: PemSection = PemSection {
    begin: "-----BEGIN PRIVATE KEY-----",
    end: "-----END PRIVATE KEY-----",
};

fn pem_to_der(pem: &str, section: &PemSection) -> Result<Vec<u8>, CertError> {
    let mut inside_section = false;
    let mut der_base64 = String::new();
    for line in pem.lines() {
        if !inside_section {
            if line == section.begin {
                inside_section = true;
            }
        } else {
            if line == section.end {
                return Ok(general_purpose::STANDARD.decode(&der_base64)?);
            }
            if inside_section {
                der_base64.push_str(line);
            }
        }
    }
    Err("Malformed PEM certificate".into())
}

#[derive(Debug)]
pub enum CertError {
    Internal(&'static str),
    Rustls(rustls::Error),
    Webpki(webpki::Error),
    VerifierBuilder(rustls::server::VerifierBuilderError),
    X509(x509_cert::der::Error),
    Base64(base64::DecodeError),
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Rustls(e) => write!(f, "Rustls error: {e}"),
            Self::Webpki(e) => write!(f, "WebPKI error: {e}"),
            Self::VerifierBuilder(e) => write!(f, "Verifier Builder error: {e}"),
            Self::X509(e) => write!(f, "X509 error: {e}"),
            Self::Base64(e) => write!(f, "Base64 decode error: {e}"),
        }
    }
}

impl error::Error for CertError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Internal(_) => None,
            Self::Rustls(err) => Some(err),
            Self::Webpki(err) => Some(err),
            Self::VerifierBuilder(err) => Some(err),
            Self::X509(_) => None,
            Self::Base64(_) => None,
        }
    }
}

impl From<&'static str> for CertError {
    fn from(msg: &'static str) -> CertError {
        Self::Internal(msg)
    }
}

impl From<rustls::Error> for CertError {
    fn from(err: rustls::Error) -> CertError {
        Self::Rustls(err)
    }
}

impl From<webpki::Error> for CertError {
    fn from(err: webpki::Error) -> CertError {
        Self::Webpki(err)
    }
}

impl From<rustls::server::VerifierBuilderError> for CertError {
    fn from(err: rustls::server::VerifierBuilderError) -> CertError {
        Self::VerifierBuilder(err)
    }
}

impl From<x509_cert::der::Error> for CertError {
    fn from(err: x509_cert::der::Error) -> CertError {
        Self::X509(err)
    }
}

impl From<base64::DecodeError> for CertError {
    fn from(err: base64::DecodeError) -> CertError {
        Self::Base64(err)
    }
}
