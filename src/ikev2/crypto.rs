use log::warn;
use rand::Rng;
use ring::{aead, agreement, digest, hkdf, hmac};
use std::{error, fmt, ops::Range};

use super::message;

const MAX_DH_KEY_LENGTH: usize = 64;
const MAX_PRF_KEY_LENGTH: usize = 256 / 8;
const MAX_AUTH_KEY_LENGTH: usize = 256 / 8;
const MAX_ENCRYPTION_KEY_LENGTH: usize = 256 / 8;
const MAX_KEY_MATERIAL_LENGTH: usize = MAX_PRF_KEY_LENGTH
    + MAX_AUTH_KEY_LENGTH * 2
    + MAX_ENCRYPTION_KEY_LENGTH * 2
    + MAX_PRF_KEY_LENGTH * 2;

#[derive(Clone, Copy, PartialEq, Eq)]
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TransformParameters {
    enc: Option<Transform>,
    prf: Option<Transform>,
    auth: Option<Transform>,
    dh: Option<Transform>,
    esn: Option<Transform>,
    protocol_id: message::IPSecProtocolID,
    local_spi: message::Spi,
    remote_spi: message::Spi,
}

impl TransformParameters {
    pub fn create_dh(&self) -> Result<DHTransformType, InitError> {
        DHTransformType::init(self.dh.as_ref().ok_or("DH not configured")?.transform_type)
    }

    pub fn create_prf(&self, key: &[u8]) -> Result<PseudorandomTransform, InitError> {
        PseudorandomTransform::init(
            self.prf
                .as_ref()
                .ok_or("PRF not configured")?
                .transform_type,
            key,
        )
    }

    pub fn protocol_id(&self) -> message::IPSecProtocolID {
        self.protocol_id
    }

    pub fn local_spi(&self) -> message::Spi {
        self.local_spi
    }

    pub fn set_local_spi(&mut self, local_spi: message::Spi) {
        self.local_spi = local_spi
    }

    pub fn remote_spi(&self) -> message::Spi {
        self.remote_spi
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

pub fn choose_sa_parameters(
    sa: &message::PayloadSecurityAssociation,
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
                local_spi: message::Spi::None,
                remote_spi: prop.spi(),
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
                    message::TransformType::ENCR_AES_GCM_16 => parameters.enc = Some(transform),
                    message::TransformType::DH_256_ECP => parameters.dh = Some(transform),
                    _ => return false,
                }
                true
            });
            if !valid {
                return None;
            }

            let enc = parameters.enc.as_ref()?;
            if enc.transform_type == message::TransformType::ENCR_AES_GCM_16
                && (enc.key_length? != 256 || parameters.auth.is_some())
            {
                return None;
            }

            if parameters.protocol_id == message::IPSecProtocolID::IKE {
                parameters.prf.as_ref()?;
                parameters.dh.as_ref()?;
            }

            Some((parameters, prop.proposal_num()))
        })
        .next()
}

pub struct Array<const M: usize> {
    data: [u8; M],
    len: usize,
}

impl<const M: usize> Array<M> {
    pub fn new(len: usize) -> Array<M> {
        Array {
            data: [0u8; M],
            len,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

pub enum DHTransformType {
    ECP256(DHTransformECP256),
}

pub trait DHTransform {
    fn read_public_key(&self) -> Array<MAX_DH_KEY_LENGTH>;

    fn key_length_bytes(&self) -> usize;

    fn shared_key_length_bytes(&self) -> usize;

    fn group_number(&self) -> u16;

    fn compute_shared_secret(
        &mut self,
        other_public_key: &[u8],
    ) -> Result<Array<MAX_DH_KEY_LENGTH>, InitError>;
}

impl DHTransformType {
    fn init(transform_type: message::TransformType) -> Result<DHTransformType, InitError> {
        match transform_type {
            message::TransformType::DH_256_ECP => {
                let rng = ring::rand::SystemRandom::new();
                let private_key =
                    match agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng) {
                        Ok(private_key) => private_key,
                        Err(_) => return Err("Failed to generate private ECDH key".into()),
                    };
                let public_key = match private_key.compute_public_key() {
                    Ok(public_key) => public_key,
                    Err(_) => return Err("Failed to compute public ECDH key".into()),
                };
                Ok(DHTransformType::ECP256(DHTransformECP256 {
                    private_key: Some(private_key),
                    public_key,
                }))
            }
            _ => Err("Unsupported DH".into()),
        }
    }
}

impl DHTransform for DHTransformType {
    fn read_public_key(&self) -> Array<MAX_DH_KEY_LENGTH> {
        match self {
            Self::ECP256(ref dh) => dh.read_public_key(),
        }
    }

    fn key_length_bytes(&self) -> usize {
        match self {
            Self::ECP256(ref dh) => dh.key_length_bytes(),
        }
    }

    fn shared_key_length_bytes(&self) -> usize {
        match self {
            Self::ECP256(ref dh) => dh.shared_key_length_bytes(),
        }
    }

    fn group_number(&self) -> u16 {
        match self {
            Self::ECP256(ref dh) => dh.group_number(),
        }
    }

    fn compute_shared_secret(
        &mut self,
        other_public_key: &[u8],
    ) -> Result<Array<MAX_DH_KEY_LENGTH>, InitError> {
        match self {
            Self::ECP256(ref mut dh) => dh.compute_shared_secret(other_public_key),
        }
    }
}

pub struct DHTransformECP256 {
    private_key: Option<agreement::EphemeralPrivateKey>,
    public_key: agreement::PublicKey,
}

impl DHTransform for DHTransformECP256 {
    fn read_public_key(&self) -> Array<MAX_DH_KEY_LENGTH> {
        let mut res = Array::new(self.key_length_bytes());
        res.as_mut_slice()
            .copy_from_slice(&self.public_key.as_ref()[1..]);
        res
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

    fn compute_shared_secret(
        &mut self,
        other_public_key: &[u8],
    ) -> Result<Array<MAX_DH_KEY_LENGTH>, InitError> {
        let mut res = Array::new(self.shared_key_length_bytes());
        let mut other_public_key_sec1 = [0u8; 1 + 64];
        other_public_key_sec1[0] = 0x04;
        other_public_key_sec1[1..].copy_from_slice(other_public_key);
        let other_public_key =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &other_public_key_sec1);
        let private_key = match self.private_key.take() {
            Some(private_key) => private_key,
            None => return Err("ECDH private key is already consumed".into()),
        };
        match agreement::agree_ephemeral(private_key, &other_public_key, |secret_point| {
            res.as_mut_slice().copy_from_slice(secret_point)
        }) {
            Ok(key) => key,
            Err(_) => {
                return Err("Failed to compute ECDH shared secret".into());
            }
        };
        Ok(res)
    }
}

pub enum PseudorandomTransform {
    None,
    HmacSha256(hkdf::Prk, Box<hmac::Key>),
}

impl PseudorandomTransform {
    fn init(
        transform_type: message::TransformType,
        key: &[u8],
    ) -> Result<PseudorandomTransform, InitError> {
        match transform_type {
            message::TransformType::PRF_HMAC_SHA2_256 => {
                let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, key);
                let key = hmac::Key::new(hmac::HMAC_SHA256, key);
                Ok(Self::HmacSha256(prk, Box::new(key)))
            }
            _ => Err("Unsupported PRF".into()),
        }
    }

    pub fn prf(&self, data: &[u8]) -> Array<MAX_PRF_KEY_LENGTH> {
        match self {
            Self::HmacSha256(_, ref key) => {
                let tag = hmac::sign(key, data);
                let mut result = Array::new(self.key_length());
                result.as_mut_slice().copy_from_slice(tag.as_ref());
                result
            }
            Self::None => Array::new(0),
        }
    }

    fn derive_keys(&self, keys: &mut DerivedKeys, data: &[u8]) -> Result<(), InitError> {
        match self {
            Self::HmacSha256(ref prk, _) => {
                let info = [data];
                let length = keys.full_length();
                let destination_length = length.0;
                let okm = if let Ok(okm) = prk.expand(&info, length) {
                    okm
                } else {
                    return Err("Failed to expand derived keys".into());
                };
                if okm.fill(&mut keys.keys[..destination_length]).is_ok() {
                    Ok(())
                } else {
                    Err("Failed to fill derived keys".into())
                }
            }
            Self::None => Err("PRF is none and cannot create new crypto stacks".into()),
        }
    }

    pub fn create_crypto_stack(
        &self,
        params: &TransformParameters,
        data: &[u8],
    ) -> Result<CryptoStack, InitError> {
        let mut keys = DerivedKeys::new_ikev2(params);
        self.derive_keys(&mut keys, data)?;
        CryptoStack::new(params, &keys)
    }

    fn key_length(&self) -> usize {
        match self {
            Self::HmacSha256(_, _) => 256 / 8,
            Self::None => 0,
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
    fn new_ikev2(params: &TransformParameters) -> DerivedKeys {
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

    fn new_esp(params: &TransformParameters) -> DerivedKeys {
        let enc_key_length = (params.enc_key_length() + params.enc_key_salt_length()) / 8;
        let auth_key_length = params.auth_key_length() / 8;
        let enc_initiator = 0..enc_key_length;
        let auth_initiator = enc_initiator.end..enc_initiator.end + auth_key_length;
        let enc_responder = auth_initiator.end..auth_initiator.end + enc_key_length;
        let auth_responder = enc_responder.end..enc_responder.end + auth_key_length;
        let derive = 0..0;
        let prf_initiator = 0..0;
        let prf_responder = 0..0;
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

    fn full_length(&self) -> DerivedKeysLength {
        let length = self.derive.len()
            + self.auth_initiator.len()
            + self.auth_responder.len()
            + self.enc_initiator.len()
            + self.enc_responder.len()
            + self.prf_initiator.len()
            + self.prf_responder.len();
        DerivedKeysLength(length)
    }
}

struct DerivedKeysLength(usize);

impl hkdf::KeyType for DerivedKeysLength {
    fn len(&self) -> usize {
        self.0
    }
}

enum Auth {
    None,
    HmacSha256tr128(AuthHmacSha256tr128),
}

impl Auth {
    fn init(transform_type: Option<message::TransformType>, key: &[u8]) -> Result<Auth, InitError> {
        match transform_type {
            Some(message::TransformType::AUTH_HMAC_SHA2_256_128) => {
                let key = hmac::Key::new(hmac::HMAC_SHA256, key);
                Ok(Self::HmacSha256tr128(AuthHmacSha256tr128 { key }))
            }
            None => Ok(Self::None),
            _ => Err("Unsupported PRF".into()),
        }
    }

    pub fn sign(&self, data: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::HmacSha256tr128(ref auth) => auth.sign(data),
            Self::None => Ok(()),
        }
    }

    pub fn validate(&self, data: &[u8]) -> bool {
        match self {
            Self::HmacSha256tr128(ref auth) => auth.validate(data),
            Self::None => true,
        }
    }

    pub fn signature_length(&self) -> usize {
        match self {
            Self::HmacSha256tr128(ref auth) => auth.signature_length(),
            Self::None => 0,
        }
    }
}

struct AuthHmacSha256tr128 {
    key: hmac::Key,
}

impl AuthHmacSha256tr128 {
    pub fn sign(&self, data: &mut [u8]) -> Result<(), CryptoError> {
        let signature_length = self.signature_length();
        if data.len() < signature_length {
            return Err("Not enough space to add signature".into());
        }
        let data_length = data.len() - signature_length;
        let tag = hmac::sign(&self.key, &data[..data_length]);
        let dest = &mut data[data_length..];
        dest.copy_from_slice(&tag.as_ref()[..signature_length]);
        Ok(())
    }

    pub fn validate(&self, data: &[u8]) -> bool {
        let signature_length = self.signature_length();
        if data.len() < signature_length {
            return false;
        }
        let received_signature = &data[data.len() - signature_length..];
        let data = &data[..data.len() - signature_length];
        let tag = hmac::sign(&self.key, data);
        &tag.as_ref()[..signature_length] == received_signature
    }

    pub fn signature_length(&self) -> usize {
        128 / 8
    }
}

pub struct CryptoStack {
    prf_child_sa: PseudorandomTransform,
    auth_initiator: Auth,
    auth_responder: Auth,
    enc_initiator: EncryptionType,
    enc_responder: EncryptionType,
    prf_initiator: PseudorandomTransform,
    prf_responder: PseudorandomTransform,
}

impl CryptoStack {
    fn new(params: &TransformParameters, keys: &DerivedKeys) -> Result<CryptoStack, InitError> {
        let enc = params
            .enc
            .as_ref()
            .ok_or("Undefined encryption parameters")?;
        let auth = params
            .auth
            .as_ref()
            .map(|transform| transform.transform_type);
        let prf = params
            .prf
            .as_ref()
            .ok_or("Undefined pseudorandom transform parameters")?
            .transform_type;
        let padding = PaddingType::from_transform(params)?;
        Ok(CryptoStack {
            prf_child_sa: PseudorandomTransform::init(prf, &keys.keys[keys.derive.clone()])?,
            auth_initiator: Auth::init(auth, &keys.keys[keys.auth_initiator.clone()])?,
            auth_responder: Auth::init(auth, &keys.keys[keys.auth_responder.clone()])?,
            enc_initiator: EncryptionType::init(
                enc,
                &keys.keys[keys.enc_initiator.clone()],
                padding,
            )?,
            enc_responder: EncryptionType::init(
                enc,
                &keys.keys[keys.enc_responder.clone()],
                padding,
            )?,
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

    pub fn create_child_stack(
        &self,
        params: &TransformParameters,
        data: &[u8],
    ) -> Result<CryptoStack, InitError> {
        let mut keys = DerivedKeys::new_esp(params);
        self.prf_child_sa.derive_keys(&mut keys, data)?;
        let enc = params
            .enc
            .as_ref()
            .ok_or("Undefined encryption parameters")?;
        let auth = params
            .auth
            .as_ref()
            .map(|transform| transform.transform_type);
        let padding = PaddingType::from_transform(params)?;
        Ok(CryptoStack {
            prf_child_sa: PseudorandomTransform::None,
            auth_initiator: Auth::init(auth, &keys.keys[keys.auth_initiator.clone()])?,
            auth_responder: Auth::init(auth, &keys.keys[keys.auth_responder.clone()])?,
            enc_initiator: EncryptionType::init(
                enc,
                &keys.keys[keys.enc_initiator.clone()],
                padding,
            )?,
            enc_responder: EncryptionType::init(
                enc,
                &keys.keys[keys.enc_responder.clone()],
                padding,
            )?,
            prf_initiator: PseudorandomTransform::None,
            prf_responder: PseudorandomTransform::None,
        })
    }

    pub fn create_rekey_stack(
        &self,
        params: &TransformParameters,
        skeyseed: &[u8],
        prf_key: &[u8],
    ) -> Result<CryptoStack, InitError> {
        let prf_transform = params.create_prf(skeyseed)?;
        prf_transform.create_crypto_stack(params, &prf_key)
    }

    pub fn rekey_skeyseed(&self, skeyseed_input: &[u8]) -> Array<MAX_PRF_KEY_LENGTH> {
        self.prf_child_sa.prf(skeyseed_input)
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
    ) -> Result<&'a [u8], CryptoError> {
        self.enc_responder.encrypt(data, msg_len, associated_data)
    }

    pub fn decrypt_data<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<&'a [u8], CryptoError> {
        self.enc_initiator.decrypt(data, msg_len, associated_data)
    }

    pub fn sign(&self, data: &mut [u8]) -> Result<(), CryptoError> {
        self.auth_responder.sign(data)
    }

    pub fn validate_signature(&self, data: &[u8]) -> bool {
        self.auth_initiator.validate(data)
    }

    pub fn authenticate_id_initiator(&self, id_initiator: &[u8], dest: &mut [u8]) {
        dest.copy_from_slice(self.prf_initiator.prf(id_initiator).as_slice())
    }

    pub fn authenticate_id_responder(&self, id_responder: &[u8], dest: &mut [u8]) {
        dest.copy_from_slice(self.prf_responder.prf(id_responder).as_slice())
    }
}

struct SliceBuffer<'a> {
    slice: &'a mut [u8],
    len: usize,
}

impl AsRef<[u8]> for SliceBuffer<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.slice[..self.len]
    }
}

impl AsMut<[u8]> for SliceBuffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.slice[..self.len]
    }
}

impl<'a> Extend<&'a u8> for SliceBuffer<'_> {
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        let remain = &mut self.slice[self.len..];
        iter.into_iter().zip(remain).for_each(|(src, dst)| {
            *dst = *src;
            self.len += 1
        });
    }
}

pub trait Encryption {
    fn encrypt<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<&'a [u8], CryptoError>;

    fn decrypt<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<&'a [u8], CryptoError>;

    fn encrypted_payload_length(&self, msg_len: usize) -> usize;
}

pub enum EncryptionType {
    AesGcm256(EncryptionAesGcm256),
}

impl EncryptionType {
    fn init(
        transform_type: &Transform,
        key: &[u8],
        padding: PaddingType,
    ) -> Result<EncryptionType, InitError> {
        match transform_type.transform_type {
            message::TransformType::ENCR_AES_GCM_16 => {
                if transform_type.key_length != Some(256) {
                    return Err("Unsupported key length".into());
                }
                let mut salt = [0u8; 4];
                salt.copy_from_slice(&key[32..]);
                let key = match aead::UnboundKey::new(&aead::AES_256_GCM, &key[..32]) {
                    Ok(key) => key,
                    Err(_) => return Err(InitError::new("Failed to init AES GCM 256 key")),
                };
                let key = aead::LessSafeKey::new(key);
                Ok(Self::AesGcm256(EncryptionAesGcm256 { key, salt, padding }))
            }
            _ => Err("ENC not initialized".into()),
        }
    }

    fn encrypted_payload_length(&self, msg_len: usize) -> usize {
        match self {
            Self::AesGcm256(ref enc) => enc.encrypted_payload_length(msg_len),
        }
    }

    fn encrypt<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<&'a [u8], CryptoError> {
        match self {
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
            Self::AesGcm256(ref dec) => dec.decrypt(data, msg_len, associated_data),
        }
    }
}

#[derive(Clone, Copy)]
enum PaddingType {
    IKEv2,
    Esp,
}

impl PaddingType {
    fn from_transform(params: &TransformParameters) -> Result<PaddingType, InitError> {
        match params.protocol_id() {
            message::IPSecProtocolID::IKE => Ok(PaddingType::IKEv2),
            message::IPSecProtocolID::ESP => Ok(PaddingType::Esp),
            _ => Err("Cannot set up padding for unsupported IPSec protocol".into()),
        }
    }

    fn remove_padding<'a>(&self, data: &'a [u8]) -> Result<&'a [u8], CryptoError> {
        if data.len() < self.length() {
            return Err("Not enough data to get padding length".into());
        }
        let padding_length = match self {
            Self::IKEv2 => data[data.len() - 1] + 1,
            Self::Esp => data[data.len() - 2] + 2,
        } as usize;
        if data.len() >= padding_length {
            Ok(&data[..data.len() - padding_length])
        } else {
            Err("Padding exceeds message size".into())
        }
    }

    fn add_padding(&self, data: &mut [u8], msg_len: usize) -> Result<(), CryptoError> {
        if data.len() < msg_len + self.length() {
            return Err("Not enough space to add padding".into());
        }
        if data.len() > 255 + msg_len + self.length() {
            return Err("Padding value overflow".into());
        }
        let padding_length = (data.len() - msg_len - self.length()) as u8;
        match self {
            Self::IKEv2 => {
                data[data.len() - 1] = padding_length;
            }
            Self::Esp => {
                // Try to detect IP protocol type based on
                // https://datatracker.ietf.org/doc/html/rfc4303#section-2.6
                // ESP sends L3 traffic, which can only be IP packets.
                data[data.len() - 1] = match data[0] >> 4 {
                    4 => 4,  //IPv4
                    6 => 41, //IPv6
                    _ => {
                        warn!("ESP IP packet is not a supported IP version: {:x}", data[0]);
                        return Err("Unsupported IP prococol version".into());
                    }
                };
                data[data.len() - 2] = padding_length;
                // RFC 4303 Section 2.4 requires alignment and specific contents for the padding field.
                let padding_range = msg_len..data.len() - 2;
                data[padding_range]
                    .iter_mut()
                    .enumerate()
                    .for_each(|(i, pad)| *pad = i as u8 + 1);
            }
        }
        Ok(())
    }

    fn length(&self) -> usize {
        match self {
            Self::IKEv2 => 1,
            Self::Esp => 2,
        }
    }

    fn pad_to_boundary(&self, msg_len: usize) -> usize {
        let padded_len = msg_len + self.length();
        match self {
            Self::IKEv2 => padded_len,
            Self::Esp => {
                const BOUNDARY: usize = 8;
                let padded_boundary = (padded_len / BOUNDARY) * BOUNDARY;
                if padded_boundary < padded_len {
                    padded_boundary + BOUNDARY
                } else {
                    padded_boundary
                }
            }
        }
    }
}

pub struct EncryptionAesGcm256 {
    key: aead::LessSafeKey,
    salt: [u8; 4],
    padding: PaddingType,
}

impl Encryption for EncryptionAesGcm256 {
    fn encrypt<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<&'a [u8], CryptoError> {
        if data.len() < self.encrypted_payload_length(msg_len) {
            return Err("Message length is too short".into());
        }
        // Pad length.
        let padded_length = self.padding.pad_to_boundary(msg_len);
        self.padding
            .add_padding(&mut data[..padded_length], msg_len)?;
        let msg_len = padded_length;
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        // Move message to the right to make space for the explicit nonce.
        data.copy_within(..msg_len, 8);
        // TODO: use a counter, and fail when all values have been used. GCM ciphers should never reuse nonces.
        rand::thread_rng()
            .try_fill(&mut nonce[4..])
            .map_err(|err| {
                warn!("Failed to generate nonce for AES GCM 16 256: {}", err);
                "Failed to generate nonce for AES GCM 16 256"
            })?;
        data[..8].copy_from_slice(&nonce[4..]);
        let mut buffer = SliceBuffer {
            slice: &mut data[8..],
            len: msg_len,
        };
        match self.key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(associated_data),
            &mut buffer,
        ) {
            Ok(()) => {
                let buffer_len = 8 + buffer.len;
                let buffer = &data[..buffer_len];
                Ok(buffer)
            }
            Err(_) => return Err("Failed to encode AES GCM 16 256 message".into()),
        }
    }

    fn decrypt<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
        associated_data: &[u8],
    ) -> Result<&'a [u8], CryptoError> {
        if msg_len <= 8 {
            return Err("Message length is too short".into());
        }
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(&data[..8]);
        match self.key.open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(associated_data),
            &mut data[8..msg_len],
        ) {
            Ok(decrypted_data) => self.padding.remove_padding(decrypted_data),
            Err(_) => Err("Failed to decode AES GCM 16 256 message".into()),
        }
    }

    fn encrypted_payload_length(&self, msg_len: usize) -> usize {
        // AES GCM is a stream cipher, encrypted payload will contain
        // part of the nonce + message (with padding) + tag.
        8 + self.padding.pad_to_boundary(msg_len) + self.key.algorithm().tag_len()
    }
}

pub fn hash_sha1(data: &[u8]) -> [u8; 20] {
    let mut result = [0u8; 20];
    let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    result.copy_from_slice(hash.as_ref());
    result
}

pub struct UnsupportedTransform {}

impl fmt::Display for UnsupportedTransform {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unsupported transform")
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

impl InitError {
    fn new(msg: &'static str) -> InitError {
        InitError { msg }
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl fmt::Debug for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl error::Error for InitError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(self)
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
        write!(f, "{}", self.msg)?;
        Ok(())
    }
}

impl fmt::Debug for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(self)
    }
}

impl From<&'static str> for CryptoError {
    fn from(msg: &'static str) -> CryptoError {
        CryptoError { msg }
    }
}
