use std::{error, fmt};

use log::debug;
use ring::{digest, signature};
use x509_parser::{
    certificate,
    extensions::GeneralName,
    oid_registry::{OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256},
    pem,
};

use super::message;

pub struct PkiProcessing {
    server_id: Option<Vec<u8>>,
    client_validation: Option<ClientValidation>,
    server_identity: Option<ServerIdentity>,
}

impl PkiProcessing {
    pub fn new(
        hostname: Option<&str>,
        root_ca: Option<&[u8]>,
        server_cert: Option<(&[u8], &[u8])>,
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
            // TODO: ensure that the server public cert is indeed signed by the root CA.
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
        let (_, client_cert) = x509_parser::parse_x509_certificate(client_cert_der)?;
        if !client_cert.validity.is_valid() {
            return Err("Client certificate has invalid date".into());
        }
        if client_cert.tbs_certificate.subject_pki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY
        {
            debug!(
                "Certificate public key algorithm {} is not supported",
                client_cert.tbs_certificate.subject_pki.algorithm.algorithm
            );
            return Err("Certificate public key algorithm is not supported".into());
        }

        if let Some(client_validation) = &self.client_validation {
            client_validation.verify_cert(&client_cert)?;
        }

        let subject_email =
            if let Some(subject_alternative_name) = client_cert.subject_alternative_name()? {
                subject_alternative_name
                    .value
                    .general_names
                    .iter()
                    .filter_map(|san| match san {
                        GeneralName::RFC822Name(email) => Some(*email),
                        _ => None,
                    })
                    .next()
            } else {
                None
            };
        let subject_cn = client_cert
            .subject
            .iter_common_name()
            .filter_map(|entry| entry.as_str().ok())
            .next();
        let subject = if let Some(subject_email) = subject_email {
            String::from(subject_email)
        } else if let Some(subject_cn) = subject_cn {
            String::from(subject_cn)
        } else {
            client_cert.tbs_certificate.subject.to_string()
        };
        let public_key = client_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .to_vec();

        Ok(ClientCertificate {
            public_key,
            subject,
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
}

const ASN1_IDENTIFIDER_ECDSA_WITH_SHA256: [u8; 12] = [
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

impl ClientCertificate {
    pub fn subject(&self) -> &str {
        self.subject.as_str()
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
                if signature_oid != &ASN1_IDENTIFIDER_ECDSA_WITH_SHA256 {
                    debug!("Unsupported ASN.1 AlgorithmIdentifier {:?}", signature_oid,);
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
    root_ca_issuer: Vec<u8>,
    root_ca_request: [u8; 20],
    root_ca_validity: x509_parser::certificate::Validity,
    root_ca_public_key: Vec<u8>,
}

impl ClientValidation {
    pub fn new(root_ca_pem: &[u8]) -> Result<ClientValidation, CertError> {
        let (_, root_ca_der) = pem::parse_x509_pem(root_ca_pem)?;
        let root_ca = root_ca_der.parse_x509()?;

        let root_ca_public_key = root_ca
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .to_vec();

        let root_ca_issuer = root_ca.tbs_certificate.subject.as_raw().to_vec();

        let mut root_ca_request = [0u8; 20];
        let root_ca_hash = digest::digest(
            &digest::SHA1_FOR_LEGACY_USE_ONLY,
            root_ca.tbs_certificate.subject_pki.raw,
        );
        root_ca_request.copy_from_slice(root_ca_hash.as_ref());

        let root_ca_validity = root_ca.validity.clone();

        Ok(ClientValidation {
            root_ca_issuer,
            root_ca_request,
            root_ca_validity,
            root_ca_public_key,
        })
    }

    fn root_ca_request(&self) -> &[u8] {
        &self.root_ca_request
    }

    fn verify_cert(&self, client_cert: &certificate::X509Certificate) -> Result<(), CertError> {
        if client_cert.tbs_certificate.issuer.as_raw() != self.root_ca_issuer {
            // This is probably unnecessary, just a quick check here.
            debug!(
                "Certificate is signed by {:?}, expecting {:?}",
                client_cert.tbs_certificate.issuer.as_raw(),
                self.root_ca_issuer
            );
            return Err("Certificate signed by another issuer".into());
        };
        if !self.root_ca_validity.is_valid() {
            return Err("Root CA certificate has invalid date".into());
        }

        let signed_data = client_cert.tbs_certificate.as_ref();
        let signature = client_cert.signature_value.as_ref();
        if client_cert.signature_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA256 {
            debug!(
                "Certificate signature algorithm {} is not supported",
                client_cert.signature_algorithm.algorithm
            );
            return Err("Certificate signature algorithm is not supported".into());
        };
        let public_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            &self.root_ca_public_key,
        );
        public_key
            .verify(&signed_data, &signature)
            .map_err(|_| "Failed to verify client cert signature")?;
        if let Some(eku) = client_cert.extended_key_usage()? {
            if !eku.value.client_auth {
                return Err("Certificate doesn't have Client Auth Extended Key Usage".into());
            }
        } else {
            return Err("Certificate doesn't specify Extended Key Usage".into());
        }

        Ok(())
    }
}

struct ServerIdentity {
    public_cert_der: Vec<u8>,
    key_pair_fixed: signature::EcdsaKeyPair,
    key_pair_asn1: signature::EcdsaKeyPair,
}

impl ServerIdentity {
    fn new(public_cert_pem: &[u8], private_key_pem: &[u8]) -> Result<ServerIdentity, CertError> {
        let (_, public_cert) = pem::parse_x509_pem(public_cert_pem)?;
        let public_cert_der = public_cert.contents;

        let (_, private_key_der) = pem::parse_x509_pem(private_key_pem)?;
        let rng = ring::rand::SystemRandom::new();
        let key_pair_fixed = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &private_key_der.contents,
            &rng,
        )
        .map_err(|_| "Failed to parse ECDSA private key")?;
        let key_pair_asn1 = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &private_key_der.contents,
            &rng,
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
        let rng = ring::rand::SystemRandom::new();
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

#[derive(Debug)]
pub enum CertError {
    Internal(&'static str),
    NomPem(x509_parser::nom::Err<x509_parser::error::PEMError>),
    NomX509(x509_parser::nom::Err<x509_parser::error::X509Error>),
    X509(x509_parser::error::X509Error),
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::NomPem(ref e) => write!(f, "PEM error: {}", e),
            Self::NomX509(ref e) => write!(f, "X509 error: {}", e),
            Self::X509(ref e) => write!(f, "X509 error: {}", e),
        }
    }
}

impl error::Error for CertError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_) => None,
            Self::NomPem(ref err) => Some(err),
            Self::NomX509(ref err) => Some(err),
            Self::X509(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for CertError {
    fn from(msg: &'static str) -> CertError {
        Self::Internal(msg)
    }
}

impl From<x509_parser::nom::Err<x509_parser::error::PEMError>> for CertError {
    fn from(err: x509_parser::nom::Err<x509_parser::error::PEMError>) -> CertError {
        Self::NomPem(err)
    }
}

impl From<x509_parser::nom::Err<x509_parser::error::X509Error>> for CertError {
    fn from(err: x509_parser::nom::Err<x509_parser::error::X509Error>) -> CertError {
        Self::NomX509(err)
    }
}

impl From<x509_parser::error::X509Error> for CertError {
    fn from(err: x509_parser::error::X509Error) -> CertError {
        Self::X509(err)
    }
}
