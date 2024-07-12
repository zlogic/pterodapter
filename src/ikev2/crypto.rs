use log::debug;
use openssl::{bn, cipher, cipher_ctx, derive, dh, ec, hash, nid, pkey, sign};
use rand::Rng;
use std::{error, fmt, ops::Range};

use super::message;

const MAX_PRF_KEY_LENGTH: usize = 256 / 8;
const MAX_AUTH_KEY_LENGTH: usize = 256 / 8;
const MAX_ENCRYPTION_KEY_LENGTH: usize = 256 / 8;
const MAX_KEY_MATERIAL_LENGTH: usize = MAX_PRF_KEY_LENGTH
    + MAX_AUTH_KEY_LENGTH * 2
    + MAX_ENCRYPTION_KEY_LENGTH * 2
    + MAX_PRF_KEY_LENGTH * 2;

pub struct Transform {
    transform_type: message::TransformType,
    key_length: Option<u16>,
}

impl Transform {
    pub fn transform_type(&self) -> message::TransformType {
        self.transform_type
    }

    pub fn key_length(&self) -> Option<u16> {
        self.key_length
    }
}

pub struct TransformParameters {
    enc: Option<Transform>,
    prf: Option<Transform>,
    auth: Option<Transform>,
    dh: Option<Transform>,
    esn: Option<Transform>,
    protocol_id: message::IPSecProtocolID,
    spi: message::SPI,
}

impl TransformParameters {
    pub fn create_dh(&self) -> Result<DHTransformType, InitError> {
        DHTransformType::init(
            self.dh
                .as_ref()
                .ok_or_else(|| "DH not configured")?
                .transform_type,
        )
    }

    pub fn create_prf(&self, key: &[u8]) -> Result<PseudorandomTransform, InitError> {
        PseudorandomTransform::init(
            self.prf
                .as_ref()
                .ok_or_else(|| "PRF not configured")?
                .transform_type,
            key,
        )
    }

    pub fn protocol_id(&self) -> message::IPSecProtocolID {
        self.protocol_id
    }

    pub fn spi(&self) -> message::SPI {
        self.spi
    }

    fn enc_key_length(&self) -> usize {
        match self.enc {
            Some(ref enc) => enc.key_length.unwrap_or(0) as usize,
            None => 0,
        }
    }

    fn enc_key_salt_length(&self) -> usize {
        match self.enc {
            Some(ref prf) => match prf.transform_type {
                message::TransformType::ENCR_AES_GCM_16 => 32,
                _ => 0,
            },
            None => 0,
        }
    }

    pub fn prf_key_length(&self) -> usize {
        match self.prf {
            Some(ref prf) => match prf.transform_type {
                message::TransformType::PRF_HMAC_SHA2_256 => 256,
                _ => 0,
            },
            None => 0,
        }
    }

    fn auth_key_length(&self) -> usize {
        match self.auth {
            Some(ref auth) => match auth.transform_type {
                message::TransformType::AUTH_HMAC_SHA2_256_128 => 256,
                _ => 0,
            },
            None => 0,
        }
    }

    pub fn auth_signature_length(&self) -> Option<usize> {
        match self.auth.as_ref()?.transform_type {
            message::TransformType::AUTH_HMAC_SHA2_256_128 => Some(128),
            _ => None,
        }
    }

    pub fn iter_parameters(&self) -> TransformParametersIter {
        TransformParametersIter {
            params: self,
            curr: 1,
        }
    }
}

pub struct TransformParametersIter<'a> {
    params: &'a TransformParameters,
    curr: usize,
}

impl<'a> Iterator for TransformParametersIter<'a> {
    type Item = &'a Transform;

    fn next(&mut self) -> Option<Self::Item> {
        for i in self.curr..=5 {
            self.curr = i + 1;
            let param = match i {
                1 => self.params.enc.as_ref(),
                2 => self.params.prf.as_ref(),
                3 => self.params.auth.as_ref(),
                4 => self.params.dh.as_ref(),
                5 => self.params.esn.as_ref(),
                _ => None,
            };
            if param.is_some() {
                return param;
            }
        }
        None
    }
}

pub fn choose_sa_parameters<'a>(
    sa: &'a message::PayloadSecurityAssociation,
) -> Option<(TransformParameters, u8)> {
    sa.iter_proposals()
        .flat_map(|prop| {
            let prop = prop.ok()?;
            let mut parameters = TransformParameters {
                enc: None,
                prf: None,
                auth: None,
                dh: None,
                esn: None,
                protocol_id: prop.protocol_id(),
                spi: prop.spi(),
            };

            let valid = prop.iter_transforms().all(|tt| {
                let tt = if let Ok(tt) = tt {
                    tt
                } else {
                    return true;
                };
                let tt_type = tt.transform_type();
                let key_length = tt
                    .iter_attributes()
                    .map(|attr| {
                        let attr = if let Ok(attr) = attr {
                            attr
                        } else {
                            return Err(UnsupportedTransform {});
                        };
                        if attr.attribute_type() != message::TransformAttributeType::KEY_LENGTH {
                            return Err(UnsupportedTransform {});
                        }
                        let value = attr.value();
                        if value.len() != 2 {
                            return Err(UnsupportedTransform {});
                        }
                        let mut key_length = [0u8; 2];
                        key_length.copy_from_slice(value);
                        let key_length = u16::from_be_bytes(key_length);
                        Ok(key_length)
                    })
                    .next();
                let key_length = match key_length {
                    Some(Ok(key_length)) => Some(key_length),
                    None => None,
                    Some(Err(_)) => return false,
                };
                // Only encryption is supposed to have a key length.
                match tt_type {
                    message::TransformType::Encryption(_) => {
                        if key_length.is_none() {
                            return false;
                        }
                    }
                    _ => {
                        if key_length.is_some() {
                            return false;
                        }
                    }
                }
                let transform = Transform {
                    transform_type: tt_type,
                    key_length,
                };
                match tt_type {
                    message::TransformType::PRF_HMAC_SHA2_256 => parameters.prf = Some(transform),
                    message::TransformType::NO_ESN => parameters.esn = Some(transform),
                    // Valid macOS options.
                    message::TransformType::ENCR_AES_GCM_16 => parameters.enc = Some(transform),
                    message::TransformType::DH_256_ECP => parameters.dh = Some(transform),
                    // Valid Windows options.
                    message::TransformType::ENCR_AES_CBC => parameters.enc = Some(transform),
                    message::TransformType::AUTH_HMAC_SHA2_256_128 => {
                        parameters.auth = Some(transform)
                    }
                    message::TransformType::DH_1024_MODP => parameters.dh = Some(transform),
                    _ => return false,
                }
                true
            });
            if !valid {
                return None;
            }

            let enc = parameters.enc.as_ref()?;
            // macOS compatibility.
            if enc.transform_type == message::TransformType::ENCR_AES_GCM_16
                && (enc.key_length? != 256 || parameters.auth.is_some())
            {
                return None;
            }
            // Windows compatibility.
            if enc.transform_type == message::TransformType::ENCR_AES_CBC
                && (enc.key_length? != 256
                    || parameters.auth.as_ref()?.transform_type
                        != message::TransformType::AUTH_HMAC_SHA2_256_128)
            {
                return None;
            }

            parameters.prf.as_ref()?;
            parameters.dh.as_ref()?;

            Some((parameters, prop.proposal_num()))
        })
        .next()
}

pub enum DHTransformType {
    MODP1024(DHTransformMODP1024),
    ECP256(DHTransformECP256),
}

pub trait DHTransform {
    fn read_public_key(&self) -> &[u8];

    fn key_length_bytes(&self) -> usize;

    fn shared_key_length_bytes(&self) -> usize;

    fn group_number(&self) -> u16;

    fn compute_shared_secret(&self, other_public_key: &[u8]) -> Result<Vec<u8>, InitError>;
}

impl DHTransformType {
    fn init(transform_type: message::TransformType) -> Result<DHTransformType, InitError> {
        match transform_type {
            message::TransformType::DH_1024_MODP => {
                let dh_instance =
                    dh::Dh::params_from_pem(DH_PARAMS_MODP_1024.as_bytes()).map_err(|err| {
                        debug!("Failed to init DH MODP 1024 instance: {}", err);
                        "Failed to init DH MODP 1024 instance"
                    })?;
                let private_key = dh_instance.generate_key().map_err(|err| {
                    debug!("Failed to generate DH MODP 1024 key: {}", err);
                    "Failed to generate DH MODP 1024 key"
                })?;
                let public_key = private_key.public_key().to_vec();
                Ok(DHTransformType::MODP1024(DHTransformMODP1024 {
                    private_key,
                    public_key,
                }))
            }
            message::TransformType::DH_256_ECP => {
                let group =
                    ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1).map_err(|err| {
                        debug!("Failed to init DH ECP 256 instance: {}", err);
                        "Failed to init DH ECP 256 instance"
                    })?;
                let private_key = ec::EcKey::generate(&group).map_err(|err| {
                    debug!("Failed to generate DH ECP 256 key: {}", err);
                    "Failed to generate DH ECP 256 key"
                })?;
                let mut ctx = bn::BigNumContext::new().map_err(|err| {
                    debug!(
                        "Failed to init math context for generating DH ECP 256 public key: {}",
                        err
                    );
                    "Failed to init math context for generating DH ECP 256 public key"
                })?;
                let public_key = private_key
                    .public_key()
                    .to_bytes(&group, ec::PointConversionForm::UNCOMPRESSED, &mut ctx)
                    .map_err(|err| {
                        debug!("Failed to generate DH ECP 256 public key: {}", err);
                        "Failed to generate DH ECP 256 public key"
                    })?;
                let private_key = pkey::PKey::from_ec_key(private_key).map_err(|err| {
                    debug!("Failed to convert DH ECP 256 private key: {}", err);
                    "Failed to convert DH ECP 256 private key"
                })?;
                Ok(DHTransformType::ECP256(DHTransformECP256 {
                    group,
                    private_key,
                    public_key,
                }))
            }
            _ => Err("Unsupported DH".into()),
        }
    }
}

impl DHTransform for DHTransformType {
    fn read_public_key(&self) -> &[u8] {
        match self {
            Self::MODP1024(ref dh) => dh.read_public_key(),
            Self::ECP256(ref dh) => dh.read_public_key(),
        }
    }

    fn key_length_bytes(&self) -> usize {
        match self {
            Self::MODP1024(ref dh) => dh.key_length_bytes(),
            Self::ECP256(ref dh) => dh.key_length_bytes(),
        }
    }

    fn shared_key_length_bytes(&self) -> usize {
        match self {
            Self::MODP1024(ref dh) => dh.shared_key_length_bytes(),
            Self::ECP256(ref dh) => dh.shared_key_length_bytes(),
        }
    }

    fn group_number(&self) -> u16 {
        match self {
            Self::MODP1024(ref dh) => dh.group_number(),
            Self::ECP256(ref dh) => dh.group_number(),
        }
    }

    fn compute_shared_secret(&self, other_public_key: &[u8]) -> Result<Vec<u8>, InitError> {
        match self {
            Self::MODP1024(ref dh) => dh.compute_shared_secret(other_public_key),
            Self::ECP256(ref dh) => dh.compute_shared_secret(other_public_key),
        }
    }
}

pub struct DHTransformMODP1024 {
    private_key: dh::Dh<pkey::Private>,
    public_key: Vec<u8>,
}

impl DHTransform for DHTransformMODP1024 {
    fn read_public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn key_length_bytes(&self) -> usize {
        1024 / 8
    }

    fn shared_key_length_bytes(&self) -> usize {
        self.key_length_bytes()
    }

    fn group_number(&self) -> u16 {
        message::TransformType::DH_1024_MODP.type_id().1
    }

    fn compute_shared_secret(&self, other_public_key: &[u8]) -> Result<Vec<u8>, InitError> {
        if other_public_key.len() != self.key_length_bytes() {
            return Err("MODP 1024 key length is not valid".into());
        }
        let other_public_key = bn::BigNum::from_slice(other_public_key).map_err(|err| {
            debug!(
                "Failed to init math context to derive DH MODP 1024 shared key: {}",
                err
            );
            "Failed to init math context to derive DH MODP 1024 shared key"
        })?;
        Ok(self
            .private_key
            .compute_key(&other_public_key)
            .map_err(|err| {
                debug!("Failed to compute DH MODP 1024 shared key: {}", err);
                "Failed to compute DH MODP 1024 shared key"
            })?)
    }
}

pub struct DHTransformECP256 {
    group: ec::EcGroup,
    private_key: pkey::PKey<pkey::Private>,
    public_key: Vec<u8>,
}

impl DHTransform for DHTransformECP256 {
    fn read_public_key(&self) -> &[u8] {
        &self.public_key[1..]
    }

    fn key_length_bytes(&self) -> usize {
        2 * 256 / 8
    }

    fn shared_key_length_bytes(&self) -> usize {
        256 / 8
    }

    fn group_number(&self) -> u16 {
        message::TransformType::DH_256_ECP.type_id().1
    }

    fn compute_shared_secret(&self, other_public_key: &[u8]) -> Result<Vec<u8>, InitError> {
        let mut other_public_key_sec1 = [0u8; 1 + 64];
        // Uncompressed form.
        other_public_key_sec1[0] = 0x04;
        other_public_key_sec1[1..].copy_from_slice(other_public_key);
        let mut ctx = bn::BigNumContext::new().map_err(|err| {
            debug!(
                "Failed to init math context to derive DH ECP 256 shared key: {}",
                err
            );
            "Failed to init math context to derive DH ECP 256 shared key"
        })?;
        let other_public_key =
            ec::EcPoint::from_bytes(&self.group, &other_public_key_sec1, &mut ctx).map_err(
                |err| {
                    debug!(
                        "Failed to convert DH ECP 256 public key into point: {}",
                        err
                    );
                    "Failed to convert DH ECP 256 public key into point"
                },
            )?;
        let other_key: pkey::PKey<_> = ec::EcKey::from_public_key(&self.group, &other_public_key)
            .map_err(|err| {
                debug!("Failed to convert DH ECP 256 public key: {}", err);
                "Failed to convert DH ECP 256 public key"
            })?
            .try_into()
            .map_err(|err| {
                debug!("Failed to convert DH ECP 256 public key: {}", err);
                "Failed to convert DH ECP 256 public key"
            })?;
        let mut deriver = derive::Deriver::new(&self.private_key).map_err(|err| {
            debug!("Failed to create DH ECP 256 deriver: {}", err);
            "Failed to create DH ECP 256 deriver"
        })?;
        deriver.set_peer(&other_key).map_err(|err| {
            debug!("Failed to set DH ECP 256 peer: {}", err);
            "Failed to set DH ECP 256 peer"
        })?;
        Ok(deriver.derive_to_vec().map_err(|err| {
            debug!("Failed to compute DH ECP 256 shared key: {}", err);
            "Failed to compute DH ECP 256 shared key"
        })?)
    }
}

pub enum PseudorandomTransform {
    HmacSha256(pkey::PKey<pkey::Private>),
}

impl PseudorandomTransform {
    fn init(
        transform_type: message::TransformType,
        key: &[u8],
    ) -> Result<PseudorandomTransform, InitError> {
        match transform_type {
            message::TransformType::PRF_HMAC_SHA2_256 => {
                let key = pkey::PKey::hmac(key).map_err(|err| {
                    debug!("Failed to init SHA256 HMAC key: {}", err);
                    "Failed to init SHA256 HMAC key"
                })?;
                Ok(Self::HmacSha256(key))
            }
            _ => Err("Unsupported PRF".into()),
        }
    }

    pub fn prf(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::HmacSha256(ref key) => {
                let mut signer = new_hmac_sha256(key).map_err(|err| {
                    debug!("Failed to init SHA256 HMAC signer: {}", err);
                    "Failed to init SHA256 HMAC signer"
                })?;
                Ok(signer.sign_oneshot_to_vec(data).map_err(|err| {
                    debug!("Failed to sign data with SHA256 HMAC: {}", err);
                    "Failed to sign data with SHA256 HMAC"
                })?)
            }
        }
    }

    pub fn create_crypto_stack(
        &self,
        params: &TransformParameters,
        data: &[u8],
    ) -> Result<CryptoStack, InitError> {
        let mut keys = DerivedKeys::new(params);
        match self {
            Self::HmacSha256(ref key) => {
                // Can OpenSSL's HKDF be used here?
                let mut signer = new_hmac_sha256(key).map_err(|err| {
                    debug!("Failed to init SHA256 HMAC signer: {}", err);
                    "Failed to init SHA256 HMAC signer"
                })?;
                let mut next_data = vec![0u8; data.len() + params.prf_key_length() / 8 + 1];
                let mut cursor = 0;
                // First T1 chunk.
                next_data[0..data.len()].copy_from_slice(data);
                next_data[data.len()] = 1;
                let mut hash = signer
                    .sign_oneshot_to_vec(&next_data[0..data.len() + 1])
                    .map_err(|err| {
                        debug!("Failed to sign PRF+ chunk: {}", err);
                        "Failed to sign PRF+ chunk"
                    })?;
                for t in 1..255 {
                    let dest_range = cursor..(cursor + hash.len()).min(keys.full_length());
                    let src_range = ..dest_range.len();
                    cursor = dest_range.end;
                    keys.keys[dest_range].copy_from_slice(&hash[src_range]);
                    if cursor >= keys.full_length() {
                        break;
                    }
                    // Following T-chunks.
                    next_data[0..hash.len()].copy_from_slice(&hash);
                    next_data[hash.len()..hash.len() + data.len()].copy_from_slice(&data);
                    next_data[hash.len() + data.len()] = t + 1;
                    let mut signer = new_hmac_sha256(key).map_err(|err| {
                        debug!("Failed to init SHA256 HMAC signer: {}", err);
                        "Failed to init SHA256 HMAC signer"
                    })?;
                    hash = signer.sign_oneshot_to_vec(&next_data).map_err(|err| {
                        debug!("Failed to sign PRF+ chunk: {}", err);
                        "Failed to sign PRF+ chunk"
                    })?;
                }
                CryptoStack::new(params, &keys)
            }
        }
    }
}

pub struct DerivedKeys {
    keys: [u8; MAX_KEY_MATERIAL_LENGTH],
    derive: Range<usize>,
    auth_initiator: Range<usize>,
    auth_responder: Range<usize>,
    enc_initiator: Range<usize>,
    enc_responder: Range<usize>,
    prf_initiator: Range<usize>,
    prf_responder: Range<usize>,
}

impl DerivedKeys {
    fn new(params: &TransformParameters) -> DerivedKeys {
        let derive_key_length = params.prf_key_length() / 8;
        let derive = 0..derive_key_length;
        let auth_key_length = params.auth_key_length() / 8;
        let auth_initiator = derive.end..derive.end + auth_key_length;
        let auth_responder = auth_initiator.end..auth_initiator.end + auth_key_length;
        let enc_key_length = (params.enc_key_length() + params.enc_key_salt_length()) / 8;
        let enc_initiator = auth_responder.end..auth_responder.end + enc_key_length;
        let enc_responder = enc_initiator.end..enc_initiator.end + enc_key_length;
        let prf_key_length = params.prf_key_length() / 8;
        let prf_initiator = enc_responder.end..enc_responder.end + prf_key_length;
        let prf_responder = prf_initiator.end..prf_initiator.end + prf_key_length;
        DerivedKeys {
            keys: [0u8; MAX_KEY_MATERIAL_LENGTH],
            derive,
            auth_initiator,
            auth_responder,
            enc_initiator,
            enc_responder,
            prf_initiator,
            prf_responder,
        }
    }

    fn full_length(&self) -> usize {
        self.prf_responder.end
    }
}

enum Auth {
    None,
    HmacSha256tr128(pkey::PKey<pkey::Private>),
}

impl Auth {
    fn init(transform_type: Option<message::TransformType>, key: &[u8]) -> Result<Auth, InitError> {
        match transform_type {
            Some(message::TransformType::AUTH_HMAC_SHA2_256_128) => {
                let key = pkey::PKey::hmac(key).map_err(|err| {
                    debug!("Failed to init SHA256-128 HMAC key: {}", err);
                    "Failed to init SHA256-128 HMAC key"
                })?;
                Ok(Self::HmacSha256tr128(key))
            }
            None => Ok(Self::None),
            _ => Err("Unsupported PRF".into()),
        }
    }

    pub fn sign(&self, data: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::HmacSha256tr128(ref key) => {
                let signature_length = self.signature_length();
                if data.len() < signature_length {
                    return Err("Not enough space to add signature".into());
                }
                let data_length = data.len() - signature_length;
                let hash = {
                    let sign_data = &data[..data_length];
                    let mut signer = new_hmac_sha256(key).map_err(|err| {
                        debug!("Failed to init SHA256-128 HMAC signer: {}", err);
                        "Failed to init SHA256-128 HMAC signer"
                    })?;
                    signer.sign_oneshot_to_vec(sign_data).map_err(|err| {
                        debug!("Failed to sign data with SHA256-128 HMAC: {}", err);
                        "Failed to sign data with SHA256-128 HMAC"
                    })?
                };
                let dest = &mut data[data_length..];
                dest.copy_from_slice(&hash[..signature_length]);
                Ok(())
            }
            Self::None => Ok(()),
        }
    }

    pub fn validate(&self, data: &[u8]) -> bool {
        match self {
            Self::HmacSha256tr128(ref key) => {
                let signature_length = self.signature_length();
                if data.len() < signature_length {
                    return false;
                }
                let received_signature = &data[data.len() - signature_length..];
                let data = &data[..data.len() - signature_length];
                let mut signer = if let Ok(signer) = new_hmac_sha256(key) {
                    signer
                } else {
                    return false;
                };
                let mut hash = [0u8; 256 / 8];
                if signer.sign_oneshot(&mut hash, data).is_err() {
                    return false;
                };
                &hash[..signature_length] == received_signature
            }
            Self::None => true,
        }
    }

    pub fn signature_length(&self) -> usize {
        match self {
            Self::HmacSha256tr128(_) => 128 / 8,
            Self::None => 0,
        }
    }
}

pub struct CryptoStack {
    derive_key: Vec<u8>,
    auth_initiator: Auth,
    auth_responder: Auth,
    enc_initiator: EncryptionType,
    enc_responder: EncryptionType,
    prf_initiator: PseudorandomTransform,
    prf_responder: PseudorandomTransform,
}

impl CryptoStack {
    fn new(params: &TransformParameters, keys: &DerivedKeys) -> Result<CryptoStack, InitError> {
        let mut derive_key = vec![0u8; keys.derive.len()];
        derive_key[0..keys.derive.len()].copy_from_slice(&keys.keys[keys.derive.clone()]);
        let enc = params
            .enc
            .as_ref()
            .ok_or_else(|| "Undefined encryption parameters")?;
        let auth = params
            .auth
            .as_ref()
            .map(|transform| transform.transform_type);
        let prf = params
            .prf
            .as_ref()
            .ok_or_else(|| "Undefined pseudorandom transform parameters")?
            .transform_type;
        Ok(CryptoStack {
            derive_key,
            auth_initiator: Auth::init(auth, &keys.keys[keys.auth_initiator.clone()])?,
            auth_responder: Auth::init(auth, &keys.keys[keys.auth_responder.clone()])?,
            enc_initiator: EncryptionType::init(enc, &keys.keys[keys.enc_initiator.clone()])?,
            enc_responder: EncryptionType::init(enc, &keys.keys[keys.enc_responder.clone()])?,
            prf_initiator: PseudorandomTransform::init(
                prf,
                &keys.keys[keys.prf_initiator.clone()],
            )?,
            prf_responder: PseudorandomTransform::init(
                prf,
                &keys.keys[keys.prf_responder.clone()],
            )?,
        })
    }

    pub fn encrypted_payload_length(&self, msg_len: usize) -> usize {
        self.enc_responder.encrypted_payload_length(msg_len)
            + self.auth_responder.signature_length()
    }

    pub fn encrypt_data<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<(), CryptoError> {
        self.enc_responder.encrypt(data, msg_len, associated_data)
    }

    pub fn decrypt_data<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<&'a [u8], CryptoError> {
        let decrypted_slice = self.enc_initiator.decrypt(data, msg_len, associated_data)?;
        let padding_length = if !decrypted_slice.is_empty() {
            decrypted_slice[decrypted_slice.len() - 1] as usize + 1
        } else {
            0
        };
        let decrypted_slice = if decrypted_slice.len() >= padding_length {
            &decrypted_slice[..decrypted_slice.len() - padding_length]
        } else {
            &decrypted_slice
        };
        Ok(decrypted_slice)
    }

    pub fn sign(&self, data: &mut [u8]) -> Result<(), CryptoError> {
        self.auth_responder.sign(data)
    }

    pub fn validate_signature(&self, data: &[u8]) -> bool {
        self.auth_initiator.validate(data)
    }

    pub fn authenticate_id_initiator(&self, id_initiator: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.prf_initiator.prf(id_initiator)
    }

    pub fn authenticate_id_responder(&self, id_responder: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.prf_responder.prf(id_responder)
    }
}

pub trait Encryption {
    fn encrypt<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<(), CryptoError>;

    fn decrypt<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<&'a [u8], CryptoError>;

    fn encrypted_payload_length(&self, msg_len: usize) -> usize;
}

pub enum EncryptionType {
    AesCbc256(EncryptionAesCbc256),
    AesGcm256(EncryptionAesGcm256),
}

impl EncryptionType {
    fn init(transform_type: &Transform, key: &[u8]) -> Result<EncryptionType, InitError> {
        match transform_type.transform_type {
            message::TransformType::ENCR_AES_CBC => {
                if transform_type.key_length != Some(256) {
                    return Err("Unsupported key length".into());
                }
                let mut cipher_key = [0u8; 256 / 8];
                cipher_key.copy_from_slice(key);
                Ok(Self::AesCbc256(EncryptionAesCbc256 { cipher_key }))
            }
            message::TransformType::ENCR_AES_GCM_16 => {
                if transform_type.key_length != Some(256) {
                    return Err("Unsupported key length".into());
                }
                let mut cipher_key = [0u8; 32];
                cipher_key.copy_from_slice(&key[..32]);
                let mut salt = [0u8; 4];
                salt.copy_from_slice(&key[32..]);
                Ok(Self::AesGcm256(EncryptionAesGcm256 { cipher_key, salt }))
            }
            _ => Err("ENC not initialized".into()),
        }
    }

    fn encrypted_payload_length(&self, msg_len: usize) -> usize {
        match self {
            Self::AesCbc256(ref enc) => enc.encrypted_payload_length(msg_len),
            Self::AesGcm256(ref enc) => enc.encrypted_payload_length(msg_len),
        }
    }

    fn encrypt<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<(), CryptoError> {
        match self {
            Self::AesCbc256(ref enc) => enc.encrypt(data, msg_len, associated_data),
            Self::AesGcm256(ref enc) => enc.encrypt(data, msg_len, associated_data),
        }
    }

    fn decrypt<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<&'a [u8], CryptoError> {
        match self {
            Self::AesCbc256(ref dec) => dec.decrypt(data, msg_len, associated_data),
            Self::AesGcm256(ref dec) => dec.decrypt(data, msg_len, associated_data),
        }
    }
}

pub struct EncryptionAesCbc256 {
    cipher_key: [u8; 256 / 8],
}

impl Encryption for EncryptionAesCbc256 {
    fn encrypt<'a>(&self, data: &'a mut [u8], msg_len: usize, _: &[u8]) -> Result<(), CryptoError> {
        let aes_cbc_cipher = cipher::Cipher::aes_256_cbc();
        let mut ctx = cipher_ctx::CipherCtx::new().map_err(|err| {
            debug!("Failed to init cipher context: {}", err);
            "Failed to init cipher context"
        })?;
        let iv_size = aes_cbc_cipher.iv_length();
        let encrypted_payload_length = self.encrypted_payload_length(msg_len);
        if data.len() < encrypted_payload_length {
            return Err("Message length is too short".into());
        }
        // Move message to the right to make space for the IV.
        data.copy_within(..msg_len, iv_size);
        let padded_msg_len = encrypted_payload_length - iv_size;
        data[encrypted_payload_length - 1] = (padded_msg_len - 1 - msg_len) as u8;
        let iv = &mut data[0..iv_size];
        rand::thread_rng().try_fill(iv).map_err(|err| {
            debug!("Failed to generate IV for AES CBC 256: {}", err);
            "Failed to generate IV for AES CBC 256"
        })?;
        ctx.encrypt_init(Some(&aes_cbc_cipher), Some(&self.cipher_key), Some(iv))
            .map_err(|err| {
                debug!("Failed to init AES CBC 256 encryptor: {}", err);
                "Failed to init AES CBC 256 encryptor"
            })?;
        /*
         * FIXME: Rust OpenSSL assumes padding is used, so needs one more data block.
         * Disabling padding means that data will not overflow, but to bypass an assertion,
         * provide a slice larger than is technically needed.
         * Even if the signature is overwritten, it shouldn't be a problem, as it's
         * checked before decrypting data.
         */
        let data_range = &mut data[iv_size..encrypted_payload_length + aes_cbc_cipher.block_size()];
        let _ = ctx
            .cipher_update_inplace(data_range, msg_len)
            .map_err(|err| {
                debug!("Failed to encode AES CBC 256 message: {}", err);
                "Failed to encode AES CBC 256 message"
            })?;
        Ok(())
    }

    fn decrypt<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        _: &[u8],
    ) -> Result<&'a [u8], CryptoError> {
        let aes_cbc_cipher = cipher::Cipher::aes_256_cbc();
        let mut ctx = cipher_ctx::CipherCtx::new().map_err(|err| {
            debug!("Failed to init cipher context: {}", err);
            "Failed to init cipher context"
        })?;
        let iv_size = aes_cbc_cipher.iv_length();
        if msg_len <= iv_size {
            return Err("Message length is too short".into());
        }
        let iv = &data[..iv_size];
        ctx.decrypt_init(Some(&aes_cbc_cipher), Some(&self.cipher_key), Some(iv))
            .map_err(|err| {
                debug!("Failed to init AES CBC 256 decryptor: {}", err);
                "Failed to init AES CBC 256 decryptor"
            })?;
        ctx.set_padding(false);
        /*
         * FIXME: Rust OpenSSL assumes padding is used, so needs one more data block.
         * Disabling padding means that data will not overflow, but to bypass an assertion,
         * provide a slice larger than is technically needed.
         * Even if the signature is overwritten, it shouldn't be a problem, as it's
         * checked before decrypting data.
         */
        let data_range = &mut data[iv_size..msg_len + aes_cbc_cipher.block_size()];
        let _ = ctx
            .cipher_update_inplace(data_range, msg_len - iv_size)
            .map_err(|err| {
                debug!("Failed to decode AES CBC 256 message: {}", err);
                "Failed to decode AES CBC 256 message"
            })?;
        Ok(&data[iv_size..msg_len])
    }

    fn encrypted_payload_length(&self, msg_len: usize) -> usize {
        let aes_cbc_cipher = cipher::Cipher::aes_256_cbc();
        let iv_size = aes_cbc_cipher.iv_length();
        let block_size = aes_cbc_cipher.block_size();
        let encrypted_size = (1 + msg_len / block_size) * block_size;
        iv_size + encrypted_size
    }
}

pub struct EncryptionAesGcm256 {
    cipher_key: [u8; 256 / 8],
    salt: [u8; 4],
}

impl Encryption for EncryptionAesGcm256 {
    fn encrypt<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<(), CryptoError> {
        if data.len() < self.encrypted_payload_length(msg_len) {
            return Err("Message length is too short".into());
        }
        // Pad length.
        data[msg_len] = 0;
        let msg_len = msg_len + 1;
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        // Move message to the right to make space for the explicit nonce.
        data.copy_within(..msg_len, 8);
        rand::thread_rng()
            .try_fill(&mut nonce[4..])
            .map_err(|err| {
                debug!("Failed to generate nonce for AES GCM 16 256: {}", err);
                "Failed to generate nonce for AES GCM 16 256"
            })?;
        data[..8].copy_from_slice(&nonce[4..]);
        let aes_gcm_cipher = cipher::Cipher::aes_256_gcm();
        let mut ctx = cipher_ctx::CipherCtx::new().map_err(|err| {
            debug!("Failed to init cipher context: {}", err);
            "Failed to init cipher context"
        })?;
        match ctx.encrypt_init(Some(&aes_gcm_cipher), Some(&self.cipher_key), Some(&nonce)) {
            Ok(dec) => dec,
            Err(err) => {
                debug!("Failed to init AES GCM 16 256: {}", err);
                return Err("Failed to init AES GCM 16 256".into());
            }
        };
        let _ = ctx.cipher_update(associated_data, None).map_err(|err| {
            debug!(
                "Failed to process AEAD data in AES GCM 16 256 message: {}",
                err
            );
            "Failed to process AEAD data in AES GCM 16 256 message"
        })?;
        let data_range = &mut data[8..8 + msg_len];
        let _ = ctx
            .cipher_update_inplace(data_range, msg_len)
            .map_err(|err| {
                debug!("Failed to encode AES GCM 16 256 message: {}", err);
                "Failed to encode AES GCM 16 256 message"
            })?;
        ctx.cipher_final(&mut [0u8; 0]).map_err(|err| {
            debug!("Failed to complete AES GCM 16 256 message: {}", err);
            "Failed to complete AES GCM 16 256 message"
        })?;
        ctx.tag(&mut data[8 + msg_len..8 + msg_len + 16])
            .map_err(|err| {
                debug!("Failed to write tag for AES GCM 16 256: {}", err);
                "Failed to write tag for AES GCM 16 256"
            })?;
        Ok(())
    }

    fn decrypt<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<&'a [u8], CryptoError> {
        if msg_len <= 16 {
            return Err("Message length is too short".into());
        }
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(&data[..8]);
        let aes_gcm_cipher = cipher::Cipher::aes_256_gcm();
        let mut ctx = cipher_ctx::CipherCtx::new().map_err(|err| {
            debug!("Failed to init cipher context: {}", err);
            "Failed to init cipher context"
        })?;
        ctx.decrypt_init(Some(&aes_gcm_cipher), Some(&self.cipher_key), Some(&nonce))
            .map_err(|err| {
                debug!("Failed to init AES GCM 16 256: {}", err);
                "Failed to init AES GCM 16 256"
            })?;
        let _ = ctx.cipher_update(associated_data, None).map_err(|err| {
            debug!(
                "Failed to process AEAD data in AES GCM 16 256 message: {}",
                err
            );
            "Failed to process AEAD data in AES GCM 16 256 message"
        })?;
        let tag = &data[msg_len - 16..msg_len];
        ctx.set_tag(tag).map_err(|err| {
            debug!("Failed to set tag for AES GCM 16 256: {}", err);
            "Failed to set tag for AES GCM 16 256"
        })?;
        let data_range = &mut data[8..msg_len - 16];
        let bytes_count = ctx
            .cipher_update_inplace(data_range, msg_len - 16 - 8)
            .map_err(|err| {
                debug!("Failed to decode AES GCM 16 256 message: {}", err);
                "Failed to decode AES GCM 16 256 message"
            })?;
        ctx.cipher_final(&mut [0u8; 0]).map_err(|err| {
            debug!("Failed to validate AES GCM 16 256 message: {}", err);
            "Failed to validate AES GCM 16 256 message"
        })?;
        Ok(&data[8..8 + bytes_count])
    }

    fn encrypted_payload_length(&self, msg_len: usize) -> usize {
        const TAG_SIZE: usize = 16;
        // AES GCM is a stream cipher, encrypted payload will contain
        // IV + message (with padding=1) + tag.
        8 + msg_len + 1 + TAG_SIZE
    }
}

fn new_hmac_sha256(
    key: &pkey::PKey<pkey::Private>,
) -> Result<sign::Signer, openssl::error::ErrorStack> {
    sign::Signer::new(hash::MessageDigest::sha256(), &key)
}

pub fn hash_sha1(data: &[u8]) -> Result<[u8; 160 / 8], CryptoError> {
    let mut hash = [0u8; 160 / 8];
    hash::hash_xof(hash::MessageDigest::sha1(), data, &mut hash).map_err(|err| {
        debug!("Failed to compute SHA1 hash: {}", err);
        "Failed to compute SHA1 hash"
    })?;
    Ok(hash)
}

pub struct UnsupportedTransform {}

impl fmt::Display for UnsupportedTransform {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unsupported transform")?;
        Ok(())
    }
}

impl fmt::Debug for UnsupportedTransform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl error::Error for UnsupportedTransform {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(self)
    }
}

pub struct InitError {
    msg: &'static str,
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.msg)
    }
}

impl fmt::Debug for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl error::Error for InitError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<&'static str> for InitError {
    fn from(msg: &'static str) -> InitError {
        InitError { msg }
    }
}

pub struct CryptoError {
    msg: &'static str,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.msg)
    }
}

impl fmt::Debug for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<&'static str> for CryptoError {
    fn from(msg: &'static str) -> CryptoError {
        CryptoError { msg }
    }
}

const DH_PARAMS_MODP_1024: &str = "-----BEGIN DH PARAMETERS-----
MIGHAoGBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJR
Sgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL
/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7OZTgf//////////AgEC
-----END DH PARAMETERS-----";
