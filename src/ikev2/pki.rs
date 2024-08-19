use std::{error, fmt};

use log::debug;
use p256::ecdsa::{self, DerSignature};
use rsa::{
    pkcs1v15,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    signature::{SignatureEncoding, Signer, Verifier},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sha1::{Digest, Sha1};
use x509_parser::{
    certificate,
    extensions::GeneralName,
    oid_registry::{OID_PKCS1_RSAENCRYPTION, OID_SIG_ECDSA_WITH_SHA256},
    pem,
};

use super::message;

#[derive(Clone)]
pub struct PkiProcessing {
    server_id: Option<Vec<u8>>,
    client_validation: Option<ClientValidation>,
    server_identity: Option<ServerIdentity>,
}

impl PkiProcessing {
    pub fn new(
        hostname: Option<&str>,
        root_ca: Option<&[u8]>,
        server_cert: Option<(&[u8], &str)>,
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
        if client_cert.tbs_certificate.subject_pki.algorithm.algorithm != OID_PKCS1_RSAENCRYPTION {
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
        let public_key_bytes = client_cert.tbs_certificate.public_key().raw;

        let public_key = RsaPublicKey::from_public_key_der(public_key_bytes)?;
        let verifying_key = pkcs1v15::VerifyingKey::new(public_key);

        Ok(ClientCertificate {
            verifying_key,
            subject,
        })
    }

    pub fn signature_length(&self) -> usize {
        if let Some(server_identity) = &self.server_identity {
            server_identity.signature_length
        } else {
            0
        }
    }

    pub fn sign_auth(&self, msg: &[u8], dest: &mut [u8]) -> Result<(), CertError> {
        if let Some(server_identity) = &self.server_identity {
            server_identity.sign_message(msg, dest)
        } else {
            Err("No server identity is configured".into())
        }
    }
}

pub struct ClientCertificate {
    verifying_key: pkcs1v15::VerifyingKey<Sha1>,
    subject: String,
}

impl ClientCertificate {
    pub fn subject(&self) -> &str {
        self.subject.as_str()
    }

    pub fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> Result<(), CertError> {
        let signature = pkcs1v15::Signature::try_from(signature)?;
        self.verifying_key.verify(msg, &signature)?;
        Ok(())
    }
}

#[derive(Clone)]
struct ClientValidation {
    root_ca_issuer: Vec<u8>,
    root_ca_request: [u8; 20],
    root_ca_validity: x509_parser::certificate::Validity,
    public_key: ecdsa::VerifyingKey,
}

impl ClientValidation {
    pub fn new(root_ca_pem: &[u8]) -> Result<ClientValidation, CertError> {
        let (_, root_ca_der) = pem::parse_x509_pem(root_ca_pem)?;
        let root_ca = root_ca_der.parse_x509()?;

        let root_ca_bytes = root_ca
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .clone();
        //    return Err("Root ca has invalid public key".into());
        let public_key = ecdsa::VerifyingKey::try_from(root_ca_bytes.as_ref())?;

        let root_ca_issuer = Vec::from(root_ca.tbs_certificate.subject.as_raw());

        let mut root_ca_request = [0u8; 20];
        root_ca_request.copy_from_slice(&root_ca.tbs_certificate.serial.to_bytes_be());
        let mut hasher = Sha1::new();
        hasher.update(root_ca.tbs_certificate.subject_pki.raw);
        let root_ca_request = hasher.finalize().into();

        let root_ca_validity = root_ca.validity.clone();

        Ok(ClientValidation {
            root_ca_issuer,
            root_ca_request,
            root_ca_validity,
            public_key,
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
        let signature = DerSignature::try_from(signature)?;
        self.public_key.verify(&signed_data, &signature)?;
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

#[derive(Clone)]
struct ServerIdentity {
    public_cert_der: Vec<u8>,
    signature_length: usize,
    signing_key: pkcs1v15::SigningKey<Sha1>,
}

impl ServerIdentity {
    fn new(public_cert_pem: &[u8], private_key_pem: &str) -> Result<ServerIdentity, CertError> {
        // TODO: if client requests cert, check if public key is signed by CA from client's CERTREQUEST.
        let (_, public_cert) = pem::parse_x509_pem(public_cert_pem)?;
        let public_cert_der = public_cert.contents;

        let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)?;
        let signature_length = private_key.size();
        let signing_key = pkcs1v15::SigningKey::<Sha1>::new(private_key);
        Ok(ServerIdentity {
            public_cert_der,
            signature_length,
            signing_key,
        })
    }

    fn public_cert_der(&self) -> &[u8] {
        &self.public_cert_der
    }

    fn sign_message(&self, msg: &[u8], dest: &mut [u8]) -> Result<(), CertError> {
        let signature = self.signing_key.try_sign(msg)?;
        dest.copy_from_slice(&signature.to_bytes());
        Ok(())
    }
}

#[derive(Debug)]
pub enum CertError {
    Internal(&'static str),
    NomPem(x509_parser::nom::Err<x509_parser::error::PEMError>),
    NomX509(x509_parser::nom::Err<x509_parser::error::X509Error>),
    X509(x509_parser::error::X509Error),
    Pkcs8(rsa::pkcs8::Error),
    Rsa(rsa::Error),
    Ecdsa(p256::ecdsa::Error),
    Spki(x509_cert::spki::Error),
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::NomPem(ref e) => write!(f, "PEM error: {}", e),
            Self::NomX509(ref e) => write!(f, "X509 error: {}", e),
            Self::X509(ref e) => write!(f, "X509 error: {}", e),
            Self::Pkcs8(ref e) => write!(f, "Decode error: {}", e),
            Self::Rsa(ref e) => write!(f, "Signature verification error: {}", e),
            Self::Ecdsa(ref e) => write!(f, "Decode error: {}", e),
            Self::Spki(ref e) => write!(f, "SPKI error: {}", e),
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
            Self::Pkcs8(ref err) => Some(err),
            Self::Rsa(ref err) => Some(err),
            Self::Ecdsa(ref err) => Some(err),
            Self::Spki(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for CertError {
    fn from(msg: &'static str) -> CertError {
        Self::Internal(msg)
    }
}

impl From<rsa::pkcs8::Error> for CertError {
    fn from(err: rsa::pkcs8::Error) -> CertError {
        Self::Pkcs8(err)
    }
}

impl From<rsa::Error> for CertError {
    fn from(err: rsa::Error) -> CertError {
        Self::Rsa(err)
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

impl From<p256::ecdsa::Error> for CertError {
    fn from(err: p256::ecdsa::Error) -> CertError {
        Self::Ecdsa(err)
    }
}

impl From<x509_cert::spki::Error> for CertError {
    fn from(err: x509_cert::spki::Error) -> CertError {
        Self::Spki(err)
    }
}
