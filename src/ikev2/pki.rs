use std::{error, fmt};

use der::{oid, Decode, DecodePem, Encode};
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
use x509_cert::{certificate, Certificate};

use super::message;

// Simpler than importing the const-oid crate.
const OID_ECDSA_WITH_SHA_256: oid::ObjectIdentifier =
    oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_RSA_ENCRYPTION: oid::ObjectIdentifier =
    oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

#[derive(Clone)]
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
        let client_cert = Certificate::from_der(client_cert_der)?;
        if !certificate_date_valid(&client_cert.tbs_certificate) {
            return Err("Client certificate has invalid date".into());
        }
        if !(client_cert
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid
            == OID_RSA_ENCRYPTION)
        {
            debug!(
                "Certificate public key algorithm {} is not supported",
                client_cert
                    .tbs_certificate
                    .subject_public_key_info
                    .algorithm
                    .oid
            );
            return Err("Certificate public key algorithm is not supported".into());
        }

        if let Some(client_validation) = &self.client_validation {
            client_validation.verify_cert(&client_cert)?;
        }

        let subject = client_cert.tbs_certificate.subject.to_string();
        let public_key_bytes = if let Ok(public_key_bytes) =
            client_cert.tbs_certificate.subject_public_key_info.to_der()
        {
            public_key_bytes
        } else {
            return Err("Certificate has no valid public key".into());
        };

        let public_key = RsaPublicKey::from_public_key_der(&public_key_bytes)?;
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
    root_ca: Certificate,
    root_ca_request: [u8; 20],
    public_key: ecdsa::VerifyingKey,
}

impl ClientValidation {
    pub fn new(root_ca_pem: &str) -> Result<ClientValidation, CertError> {
        let root_ca = Certificate::from_pem(&root_ca_pem)?;

        let root_ca_bytes = if let Some(root_ca_bytes) = root_ca
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
        {
            root_ca_bytes
        } else {
            return Err("Root ca has invalid public key".into());
        };
        let public_key = ecdsa::VerifyingKey::try_from(root_ca_bytes)?;

        let mut hasher = Sha1::new();
        hasher.update(root_ca.tbs_certificate.subject_public_key_info.to_der()?);
        let root_ca_request = hasher.finalize().into();

        Ok(ClientValidation {
            root_ca,
            root_ca_request,
            public_key,
        })
    }

    fn root_ca_request(&self) -> &[u8] {
        &self.root_ca_request
    }

    fn verify_cert(&self, client_cert: &Certificate) -> Result<(), CertError> {
        if client_cert.tbs_certificate.issuer != self.root_ca.tbs_certificate.subject {
            // This is probably unnecessary, just a quick check here.
            debug!(
                "Certificate is signed by {}, expecting {}",
                client_cert.tbs_certificate.subject, self.root_ca.tbs_certificate.issuer
            );
            return Err("Certificate signed by another issuer".into());
        };
        if !certificate_date_valid(&self.root_ca.tbs_certificate) {
            return Err("Root CA certificate has invalid date".into());
        }

        let signed_data = client_cert.tbs_certificate.to_der()?;
        let signature = match client_cert.signature.as_bytes() {
            Some(signature) => signature,
            None => return Err("Client cert has no valid signature".into()),
        };
        if !(client_cert.signature_algorithm.oid == OID_ECDSA_WITH_SHA_256) {
            debug!(
                "Certificate signature algorithm {} is not supported",
                client_cert.signature_algorithm.oid
            );
            return Err("Certificate signature algorithm is not supported".into());
        };
        let signature = DerSignature::try_from(signature)?;
        self.public_key.verify(&signed_data, &signature)?;
        /* TODO: check the following extensions:
        - Subject Alternative Name (OID 2.5.29.17)
        - Enhanced Key Usage (OID 2.5.29.37)
        Each needs a custom DecodeValue trait/implementation for the der crate;
        most likely with a #[derive(Choice)] annotation.
        */

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
    fn new(public_cert_pem: &str, private_key_pem: &str) -> Result<ServerIdentity, CertError> {
        // TODO: if client requests cert, check if public key is signed by CA from client's CERTREQUEST.
        let public_cert_der = Certificate::from_pem(&public_cert_pem)?;
        let public_cert_der = public_cert_der.to_der()?;

        let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem)?;
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

fn certificate_date_valid(cert: &certificate::TbsCertificateInner) -> bool {
    let time_now = std::time::SystemTime::now();
    cert.validity.not_before.to_system_time() < time_now
        && cert.validity.not_after.to_system_time() > time_now
}

#[derive(Debug)]
pub enum CertError {
    Internal(&'static str),
    Pkcs8(rsa::pkcs8::Error),
    Rsa(rsa::Error),
    Der(der::Error),
    Ecdsa(p256::ecdsa::Error),
    Spki(x509_cert::spki::Error),
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::Pkcs8(ref e) => write!(f, "Decode error: {}", e),
            Self::Rsa(ref e) => write!(f, "Signature verification error: {}", e),
            Self::Der(ref e) => write!(f, "Decode error: {}", e),
            Self::Ecdsa(ref e) => write!(f, "Decode error: {}", e),
            Self::Spki(ref e) => write!(f, "Decode error: {}", e),
        }
    }
}

impl error::Error for CertError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::Pkcs8(ref err) => Some(err),
            Self::Rsa(ref err) => Some(err),
            Self::Der(ref err) => Some(err),
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

impl From<der::Error> for CertError {
    fn from(err: der::Error) -> CertError {
        Self::Der(err)
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
