use aes::{
    cipher::{BlockDecryptMut, BlockEncryptMut},
    Aes256,
};
use aes_gcm::{
    aead::{AeadMutInPlace, Buffer},
    Aes256Gcm, Nonce,
};
use cipher::{block_padding, InnerIvInit, IvSizeUser};
use crypto_bigint::{
    modular::constant_mod::{self, ResidueParams},
    Encoding,
};
use hmac::{Hmac, Mac};
use log::debug;
use p256::{elliptic_curve::sec1::Tag, EncodedPoint, NonZeroScalar, ProjectivePoint, PublicKey};
use sha2::Sha256;
use std::{error, fmt, ops::Range};

use crypto_bigint::{const_residue, impl_modulus, rand_core::OsRng, Random, U1024};

use super::message;

const MAX_DH_KEY_LENGTH: usize = 1024 / 8;
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
    pub fn create_dh(&self) -> Result<DHTransform, InitError> {
        DHTransform::init(
            self.dh
                .as_ref()
                .ok_or_else(|| InitError::new("DH not configured"))?
                .transform_type,
        )
    }

    pub fn create_prf(&self, key: &[u8]) -> Result<PseudorandomTransform, InitError> {
        PseudorandomTransform::init(
            self.prf
                .as_ref()
                .ok_or_else(|| InitError::new("PRF not configured"))?
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

    fn prf_key_length(&self) -> usize {
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

    pub fn auth_signature_length(&self) -> usize {
        match self.auth {
            Some(ref auth) => match auth.transform_type {
                message::TransformType::AUTH_HMAC_SHA2_256_128 => 128,
                _ => 0,
            },
            None => 0,
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
                    // Valid macOS options.
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

            // TODO: support more combinations.
            // TODO: init encryption handlers.
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

pub enum DHTransform {
    MODP1024(u16, U1024, U1024),
    ECP256(u16, NonZeroScalar, PublicKey),
}

impl DHTransform {
    fn init(transform_type: message::TransformType) -> Result<DHTransform, InitError> {
        let (_, dh_group) = transform_type.type_id();
        match transform_type {
            message::TransformType::DH_1024_MODP => {
                let private_key = U1024::random(&mut OsRng);
                // This calculates DH_MODP_GENERATOR_1024^private_key mod DHModulus1024.
                let public_key = DH_MODP_RESIDUE_1024.pow(&private_key).retrieve();
                Ok(DHTransform::MODP1024(dh_group, private_key, public_key))
            }
            message::TransformType::DH_256_ECP => {
                let private_key = NonZeroScalar::random(&mut OsRng);
                let public_key = PublicKey::from_secret_scalar(&private_key);
                Ok(DHTransform::ECP256(dh_group, private_key, public_key))
            }
            _ => Err("Unsupported DH".into()),
        }
    }

    pub fn read_public_key(&self) -> Array<MAX_DH_KEY_LENGTH> {
        let mut res = Array::new(self.key_length_bytes());
        match self {
            Self::MODP1024(_, _, public_key) => res
                .as_mut_slice()
                .copy_from_slice(&public_key.to_be_bytes()),
            Self::ECP256(_, _, public_key) => res
                .as_mut_slice()
                .copy_from_slice(&EncodedPoint::from(public_key).as_bytes()[1..]),
        }
        res
    }

    pub fn key_length_bytes(&self) -> usize {
        match self {
            Self::MODP1024(_, _, _) => 1024 / 8,
            Self::ECP256(_, _, _) => 2 * 256 / 8,
        }
    }

    fn shared_key_length_bytes(&self) -> usize {
        match self {
            Self::MODP1024(_, _, _) => self.key_length_bytes(),
            Self::ECP256(_, _, _) => 256 / 8,
        }
    }

    pub fn group_number(&self) -> u16 {
        match self {
            Self::MODP1024(group, _, _) => *group,
            Self::ECP256(group, _, _) => *group,
        }
    }

    pub fn compute_shared_secret(
        &self,
        other_public_key: &[u8],
    ) -> Result<Array<MAX_DH_KEY_LENGTH>, InitError> {
        let mut res = Array::new(self.shared_key_length_bytes());
        match self {
            Self::MODP1024(_, private_key, _) => {
                if other_public_key.len() != self.key_length_bytes() {
                    return Err("MODP 1024 key length is not valid".into());
                }
                let other_public_key = U1024::from_be_slice(other_public_key);
                let other_key_residue = const_residue!(other_public_key, DHModulus1024);
                let shared_key = other_key_residue.pow(&private_key).retrieve();
                res.as_mut_slice()
                    .copy_from_slice(&shared_key.to_be_bytes());
            }
            Self::ECP256(_, private_key, _) => {
                let mut other_public_key_sec1 = [0u8; 1 + 64];
                other_public_key_sec1[0] = Tag::Uncompressed.into();
                other_public_key_sec1[1..].copy_from_slice(other_public_key);
                let other_public_key = match PublicKey::from_sec1_bytes(&other_public_key_sec1) {
                    Ok(key) => key,
                    Err(err) => {
                        debug!("Failed to decode other public key {}", err);
                        return Err("Failed to decode other public key".into());
                    }
                };
                let public_point = ProjectivePoint::from(other_public_key.as_affine());
                let secret_point = (&public_point * private_key).to_affine();
                res.as_mut_slice()
                    .copy_from_slice(&EncodedPoint::from(secret_point).compress().as_bytes()[1..]);
            }
        }
        Ok(res)
    }
}

type HmacSha256 = Hmac<Sha256>;

pub enum PseudorandomTransform {
    HmacSha256(HmacSha256),
}

impl PseudorandomTransform {
    fn init(
        transform_type: message::TransformType,
        key: &[u8],
    ) -> Result<PseudorandomTransform, InitError> {
        match transform_type {
            message::TransformType::PRF_HMAC_SHA2_256 => {
                let core_wrapper = HmacSha256::new_from_slice(key)
                    .map_err(|_| InitError::new("Failed to init HMAC SHA256 PRF"))?;
                let hmac = core_wrapper;
                Ok(Self::HmacSha256(hmac))
            }
            _ => Err("Unsupported PRF".into()),
        }
    }

    pub fn prf(&mut self, data: &[u8]) -> Array<MAX_PRF_KEY_LENGTH> {
        match self {
            Self::HmacSha256(ref mut hmac) => {
                const BLOCK_LENGTH: usize = 256 / 8;
                hmac.update(data);
                let hash = hmac.finalize_reset().into_bytes();
                let mut result = Array::new(BLOCK_LENGTH);
                result.as_mut_slice().copy_from_slice(&hash);
                result
            }
        }
    }

    pub fn create_crypto_stack(
        &mut self,
        params: &TransformParameters,
        data: &[u8],
    ) -> Result<CryptoStack, InitError> {
        let mut keys = DerivedKeys::new(params);
        match self {
            Self::HmacSha256(ref mut hmac) => {
                let mut next_data = vec![0u8; data.len() + params.prf_key_length() / 8 + 1];
                let mut cursor = 0;
                // First T1 chunk.
                next_data[0..data.len()].copy_from_slice(data);
                next_data[data.len()] = 1;
                hmac.update(&next_data[0..data.len() + 1]);
                for t in 1..255 {
                    let hash = hmac.finalize_reset().into_bytes();
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
                    hmac.update(&next_data);
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
    HmacSha256tr128(HmacSha256),
}

impl Auth {
    fn init(transform_type: Option<message::TransformType>, key: &[u8]) -> Result<Auth, InitError> {
        match transform_type {
            Some(message::TransformType::AUTH_HMAC_SHA2_256_128) => {
                let core_wrapper = HmacSha256::new_from_slice(key)
                    .map_err(|_| InitError::new("Failed to init HMAC SHA256-128 AUTH"))?;
                let hmac = core_wrapper;
                Ok(Self::HmacSha256tr128(hmac))
            }
            None => Ok(Self::None),
            _ => Err("Unsupported PRF".into()),
        }
    }

    pub fn validate(&mut self, data: &[u8]) -> bool {
        match self {
            Self::HmacSha256tr128(ref mut hmac) => {
                const SIGNATURE_LENGTH: usize = 128 / 8;
                if data.len() < SIGNATURE_LENGTH {
                    return false;
                }
                let received_signature = &data[data.len() - SIGNATURE_LENGTH..];
                let data = &data[..data.len() - SIGNATURE_LENGTH];
                hmac.update(data);
                let hash = hmac.finalize_reset().into_bytes();
                hash.iter()
                    .take(SIGNATURE_LENGTH)
                    .zip(received_signature.iter())
                    .all(|(expected, received)| expected == received)
            }
            Self::None => true,
        }
    }
}

pub struct CryptoStack {
    derive_key: Array<MAX_PRF_KEY_LENGTH>,
    auth_initiator: Auth,
    auth_responder: Auth,
    enc_initiator: Encryption,
    enc_responder: Encryption,
}

impl CryptoStack {
    fn new(params: &TransformParameters, keys: &DerivedKeys) -> Result<CryptoStack, InitError> {
        let mut derive_key = Array::new(keys.derive.len());
        derive_key.data[0..keys.derive.len()].copy_from_slice(&keys.keys[keys.derive.clone()]);
        let enc = params
            .enc
            .as_ref()
            .ok_or_else(|| InitError::new("Undefined encryption parameters"))?;
        let auth = params
            .auth
            .as_ref()
            .map(|transform| transform.transform_type);
        Ok(CryptoStack {
            derive_key,
            auth_initiator: Auth::init(auth, &keys.keys[keys.auth_initiator.clone()])?,
            auth_responder: Auth::init(auth, &keys.keys[keys.auth_responder.clone()])?,
            enc_initiator: Encryption::init(enc, &keys.keys[keys.enc_initiator.clone()])?,
            enc_responder: Encryption::init(enc, &keys.keys[keys.enc_responder.clone()])?,
        })
    }

    pub fn decrypt_data<'a>(
        &self,
        data: &'a mut [u8],
        msg_len: usize,
    ) -> Result<&'a [u8], CryptoError> {
        self.enc_initiator.decrypt(data, msg_len)
    }

    pub fn validate_signature(&mut self, data: &[u8]) -> bool {
        self.auth_initiator.validate(data)
    }
}

type AesCbc256Decryptor = cbc::Decryptor<Aes256>;
type AesCbc256Encryptor = cbc::Encryptor<Aes256>;

pub enum Encryption {
    AesCbc256(Aes256),
    AesGcm256(Aes256Gcm, [u8; 4]),
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

impl Buffer for SliceBuffer<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm::aead::Result<()> {
        if self.len + other.len() <= self.slice.len() {
            self.slice[self.len..self.len + other.len()].copy_from_slice(other);
            self.len += other.len();
            Ok(())
        } else {
            Err(aes_gcm::aead::Error)
        }
    }

    fn truncate(&mut self, len: usize) {
        self.len = len;
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Encryption {
    fn init(transform_type: &Transform, key: &[u8]) -> Result<Encryption, InitError> {
        match transform_type.transform_type {
            message::TransformType::ENCR_AES_CBC => {
                if transform_type.key_length != Some(256) {
                    return Err("Unsupported key length".into());
                }
                let cipher = aes::cipher::KeyInit::new_from_slice(key)
                    .map_err(|_| InitError::new("Failed to init AES CBC 256 cipher"))?;
                Ok(Self::AesCbc256(cipher))
            }
            message::TransformType::ENCR_AES_GCM_16 => {
                if transform_type.key_length != Some(256) {
                    return Err("Unsupported key length".into());
                }
                let cipher = aes_gcm::KeyInit::new_from_slice(&key[..32])
                    .map_err(|_| InitError::new("Failed to init AES GCM 256 cipher"))?;
                let mut salt = [0u8; 4];
                salt.copy_from_slice(&key[32..]);
                Ok(Self::AesGcm256(cipher, salt))
            }
            _ => Err("ENC not initialized".into()),
        }
    }

    fn encrypt<'a>(&self, data: &'a mut [u8], msg_len: usize) -> Option<&'a [u8]> {
        match self {
            Self::AesCbc256(ref cipher) => None,
            Self::AesGcm256(ref cipher, salt) => {
                None
                //cipher.encrypt_in_place(data, msg_len);
            }
        }
    }

    fn decrypt<'a>(&self, data: &'a mut [u8], msg_len: usize) -> Result<&'a [u8], CryptoError> {
        match self {
            Self::AesCbc256(ref cipher) => {
                let iv_size = AesCbc256Decryptor::iv_size();
                if msg_len <= iv_size {
                    return Err("Message length is too short".into());
                }
                let block_decryptor =
                    match AesCbc256Decryptor::inner_iv_slice_init(cipher.clone(), &data[..iv_size])
                    {
                        Ok(dec) => dec,
                        Err(err) => {
                            debug!("Failed to init AES CBC 256 IV: {}", err);
                            return Err("Failed to init AES CBC 256 IV".into());
                        }
                    };
                let data_range = &mut data[iv_size..msg_len];
                match block_decryptor.decrypt_padded_mut::<block_padding::Iso10126>(data_range) {
                    Ok(data) => Ok(data),
                    Err(err) => {
                        debug!("Failed to decode AES CBC 256 message: {}", err);
                        return Err("Failed to decode AES CBC 256 message".into());
                    }
                }
            }
            Self::AesGcm256(ref cipher, salt) => {
                if msg_len <= 8 {
                    return Err("Message length is too short".into());
                }
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(salt);
                nonce[4..].copy_from_slice(&data[..8]);
                let mut buffer = SliceBuffer {
                    slice: &mut data[8..],
                    len: msg_len - 8,
                };
                let mut cipher = cipher.clone();
                match cipher.decrypt_in_place(Nonce::from_slice(nonce.as_slice()), &[], &mut buffer)
                {
                    Ok(()) => Ok(&buffer.slice[..buffer.len]),
                    Err(err) => {
                        debug!("Failed to decode AES GCM 16 256 message: {}", err);
                        return Err("Failed to decode AES GCM 16 256 message".into());
                    }
                }
            }
        }
    }
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

impl InitError {
    fn new(msg: &'static str) -> InitError {
        InitError { msg }
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)?;
        Ok(())
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
        InitError::new(msg)
    }
}

pub struct CryptoError {
    msg: &'static str,
}

impl CryptoError {
    fn new(msg: &'static str) -> CryptoError {
        CryptoError { msg }
    }
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
        CryptoError::new(msg)
    }
}

const DH_MODP_GENERATOR_1024: U1024 = U1024::from_u8(2);
const DH_MODP_RESIDUE_1024: constant_mod::Residue<DHModulus1024, { U1024::LIMBS }> =
    const_residue!(DH_MODP_GENERATOR_1024, DHModulus1024);

impl_modulus!(
    DHModulus1024,
    U1024,
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
);
