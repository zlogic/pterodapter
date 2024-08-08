use std::{error, fmt};

use log::debug;
use openssl::{asn1, hash, nid, pkey, sign, x509};

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
        let client_cert = x509::X509::from_der(client_cert_der)?;
        if !certificate_date_valid(&client_cert) {
            return Err("Client certificate has invalid date".into());
        }

        if let Some(client_validation) = &self.client_validation {
            client_validation.verify_cert(&client_cert)?;
        }
        let public_key = client_cert.public_key()?;

        if !(public_key.id() == pkey::Id::RSA) {
            debug!(
                "Certificate public key algorithm {} is not supported",
                public_key.id().as_raw()
            );
            return Err("Certificate public key algorithm is not supported".into());
        }

        let subject_email = if let Some(sans) = client_cert.subject_alt_names() {
            sans.iter()
                .filter_map(|san| Some(san.email()?.to_string()))
                .next()
        } else {
            None
        };
        let subject_cn = client_cert
            .subject_name()
            .entries()
            .filter_map(|entry| {
                if entry.object().nid() == nid::Nid::COMMONNAME {
                    Some(entry.data().as_utf8().ok()?.to_string())
                } else {
                    None
                }
            })
            .next();
        let subject = if subject_email.is_some() {
            subject_email
        } else if subject_cn.is_some() {
            subject_cn
        } else {
            None
        };

        Ok(ClientCertificate {
            public_key,
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
    public_key: pkey::PKey<pkey::Public>,
    subject: Option<String>,
}

impl ClientCertificate {
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    pub fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> Result<(), CertError> {
        let mut verifier = sign::Verifier::new(hash::MessageDigest::sha1(), &self.public_key)?;
        if !verifier.verify_oneshot(signature, msg)? {
            Err("Signature verification failed".into())
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
struct ClientValidation {
    root_ca: x509::X509,
    root_ca_request: [u8; 20],
    public_key: pkey::PKey<pkey::Public>,
}

impl ClientValidation {
    pub fn new(root_ca_pem: &str) -> Result<ClientValidation, CertError> {
        let root_ca = x509::X509::from_pem(root_ca_pem.as_bytes())?;

        let public_key = root_ca.public_key()?;

        let mut root_ca_request = [0u8; 20];
        hash::hash_xof(
            hash::MessageDigest::sha1(),
            public_key.public_key_to_der()?.as_slice(),
            &mut root_ca_request,
        )?;

        Ok(ClientValidation {
            root_ca,
            root_ca_request,
            public_key,
        })
    }

    fn root_ca_request(&self) -> &[u8] {
        &self.root_ca_request
    }

    fn verify_cert(&self, client_cert: &x509::X509) -> Result<(), CertError> {
        if !certificate_date_valid(&self.root_ca) {
            return Err("Root CA certificate has invalid date".into());
        }

        if !client_cert.verify(&self.public_key)? {
            return Err("Certificate verification failed".into());
        }
        if self.root_ca.issued(client_cert) != x509::X509VerifyResult::OK {
            return Err("Certificate was not issued by the root CA".into());
        }
        /* TODO: check the following extensions:
        - Subject Alternative Name (OID 2.5.29.17) (matches root CA limitations)
        - Enhanced Key Usage (OID 2.5.29.37)
        */

        Ok(())
    }
}

#[derive(Clone)]
struct ServerIdentity {
    public_cert_der: Vec<u8>,
    signature_length: usize,
    private_key: pkey::PKey<pkey::Private>,
}

impl ServerIdentity {
    fn new(public_cert_pem: &str, private_key_pem: &str) -> Result<ServerIdentity, CertError> {
        // TODO: if client requests cert, check if public key is signed by CA from client's CERTREQUEST.
        let public_cert_der = x509::X509::from_pem(public_cert_pem.as_bytes())?;
        let public_cert_der = public_cert_der.to_der()?;

        let private_key = pkey::PKey::private_key_from_pem(private_key_pem.as_bytes())?;
        let signature_length = private_key.size();
        Ok(ServerIdentity {
            public_cert_der,
            signature_length,
            private_key,
        })
    }

    fn public_cert_der(&self) -> &[u8] {
        &self.public_cert_der
    }

    fn sign_message(&self, msg: &[u8], dest: &mut [u8]) -> Result<(), CertError> {
        let mut signer = sign::Signer::new(hash::MessageDigest::sha1(), &self.private_key)?;
        signer.sign_oneshot(dest, msg)?;
        Ok(())
    }
}

fn certificate_date_valid(cert: &x509::X509) -> bool {
    let time_now = match asn1::Asn1Time::days_from_now(0) {
        Ok(time) => time,
        Err(err) => {
            debug!("Failed to get current time in ASN format: {}", err);
            return false;
        }
    };
    cert.not_before() < time_now && cert.not_after() > time_now
}

#[derive(Debug)]
pub enum CertError {
    Internal(&'static str),
    OpenSSL(openssl::error::ErrorStack),
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Internal(msg) => f.write_str(msg),
            Self::OpenSSL(ref e) => write!(f, "OpenSSL error: {}", e),
        }
    }
}

impl error::Error for CertError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Self::Internal(_msg) => None,
            Self::OpenSSL(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for CertError {
    fn from(msg: &'static str) -> CertError {
        Self::Internal(msg)
    }
}

impl From<openssl::error::ErrorStack> for CertError {
    fn from(err: openssl::error::ErrorStack) -> CertError {
        Self::OpenSSL(err)
    }
}
