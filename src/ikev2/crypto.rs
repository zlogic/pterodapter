use aes::{
    cipher::{BlockDecryptMut, BlockEncryptMut},
    Aes256,
};
use aes_gcm::{
    aead::{AeadMutInPlace, Buffer},
    Aes256Gcm, Nonce,
};
use cipher::{block_padding, BlockSizeUser, InnerIvInit, Iv, IvSizeUser};
use crypto_bigint::{
    modular::constant_mod::{self, ResidueParams},
    Encoding,
};
use hmac::{Hmac, Mac};
use log::debug;
use p256::{
    elliptic_curve::sec1::Tag as P256Tag, EncodedPoint, NonZeroScalar, ProjectivePoint, PublicKey,
};
use rand::Rng;
use sha1::{Digest, Sha1};
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
                message::TransformType::AUTH_HMAC_SHA1_96 => 160,
                _ => 0,
            },
            None => 0,
        }
    }

    pub fn auth_signature_length(&self) -> Option<usize> {
        match self.auth.as_ref()?.transform_type {
            message::TransformType::AUTH_HMAC_SHA2_256_128 => Some(128),
            message::TransformType::AUTH_HMAC_SHA1_96 => Some(96),
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
                    // Valid macOS options.
                    message::TransformType::ENCR_AES_GCM_16 => parameters.enc = Some(transform),
                    message::TransformType::DH_256_ECP => parameters.dh = Some(transform),
                    // Valid Windows options.
                    message::TransformType::ENCR_AES_CBC => parameters.enc = Some(transform),
                    message::TransformType::AUTH_HMAC_SHA2_256_128 => {
                        parameters.auth = Some(transform)
                    }
                    message::TransformType::AUTH_HMAC_SHA1_96 => parameters.auth = Some(transform),
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
                && (enc.key_length? != 256 || parameters.auth.is_none())
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
    MODP1024(DHTransformMODP1024),
    ECP256(DHTransformECP256),
}

pub trait DHTransform {
    fn read_public_key(&self) -> Array<MAX_DH_KEY_LENGTH>;

    fn key_length_bytes(&self) -> usize;

    fn shared_key_length_bytes(&self) -> usize;

    fn group_number(&self) -> u16;

    fn compute_shared_secret(
        &self,
        other_public_key: &[u8],
    ) -> Result<Array<MAX_DH_KEY_LENGTH>, InitError>;
}

impl DHTransformType {
    fn init(transform_type: message::TransformType) -> Result<DHTransformType, InitError> {
        match transform_type {
            message::TransformType::DH_1024_MODP => {
                let private_key = U1024::random(&mut OsRng);
                // This calculates DH_MODP_GENERATOR_1024^private_key mod DHModulus1024.
                let public_key = DH_MODP_RESIDUE_1024.pow(&private_key).retrieve();
                Ok(DHTransformType::MODP1024(DHTransformMODP1024 {
                    private_key,
                    public_key,
                }))
            }
            message::TransformType::DH_256_ECP => {
                let private_key = NonZeroScalar::random(&mut OsRng);
                let public_key = PublicKey::from_secret_scalar(&private_key);
                Ok(DHTransformType::ECP256(DHTransformECP256 {
                    private_key,
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

    fn compute_shared_secret(
        &self,
        other_public_key: &[u8],
    ) -> Result<Array<MAX_DH_KEY_LENGTH>, InitError> {
        match self {
            Self::MODP1024(ref dh) => dh.compute_shared_secret(other_public_key),
            Self::ECP256(ref dh) => dh.compute_shared_secret(other_public_key),
        }
    }
}

pub struct DHTransformMODP1024 {
    public_key: U1024,
    private_key: U1024,
}

impl DHTransform for DHTransformMODP1024 {
    fn read_public_key(&self) -> Array<MAX_DH_KEY_LENGTH> {
        let mut res = Array::new(self.key_length_bytes());
        res.as_mut_slice()
            .copy_from_slice(&self.public_key.to_be_bytes());
        res
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

    fn compute_shared_secret(
        &self,
        other_public_key: &[u8],
    ) -> Result<Array<MAX_DH_KEY_LENGTH>, InitError> {
        let mut res = Array::new(self.shared_key_length_bytes());
        if other_public_key.len() != self.key_length_bytes() {
            return Err("MODP 1024 key length is not valid".into());
        }
        let other_public_key = U1024::from_be_slice(other_public_key);
        let other_key_residue = const_residue!(other_public_key, DHModulus1024);
        let shared_key = other_key_residue.pow(&self.private_key).retrieve();
        res.as_mut_slice()
            .copy_from_slice(&shared_key.to_be_bytes());
        Ok(res)
    }
}

pub struct DHTransformECP256 {
    private_key: NonZeroScalar,
    public_key: PublicKey,
}

impl DHTransform for DHTransformECP256 {
    fn read_public_key(&self) -> Array<MAX_DH_KEY_LENGTH> {
        let mut res = Array::new(self.key_length_bytes());
        res.as_mut_slice()
            .copy_from_slice(&EncodedPoint::from(&self.public_key).as_bytes()[1..]);
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
        &self,
        other_public_key: &[u8],
    ) -> Result<Array<MAX_DH_KEY_LENGTH>, InitError> {
        let mut res = Array::new(self.shared_key_length_bytes());
        let mut other_public_key_sec1 = [0u8; 1 + 64];
        other_public_key_sec1[0] = P256Tag::Uncompressed.into();
        other_public_key_sec1[1..].copy_from_slice(other_public_key);
        let other_public_key = match PublicKey::from_sec1_bytes(&other_public_key_sec1) {
            Ok(key) => key,
            Err(err) => {
                debug!("Failed to decode other public key {}", err);
                return Err("Failed to decode other public key".into());
            }
        };
        let public_point = ProjectivePoint::from(other_public_key.as_affine());
        let secret_point = (&public_point * &self.private_key).to_affine();
        res.as_mut_slice()
            .copy_from_slice(&EncodedPoint::from(secret_point).compress().as_bytes()[1..]);
        Ok(res)
    }
}

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

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

    pub fn prf(&self, data: &[u8]) -> Array<MAX_PRF_KEY_LENGTH> {
        match self {
            Self::HmacSha256(ref hmac) => {
                const BLOCK_LENGTH: usize = 256 / 8;
                let mut hmac = hmac.clone();
                hmac.update(data);
                let hash = hmac.finalize().into_bytes();
                let mut result = Array::new(BLOCK_LENGTH);
                result.as_mut_slice().copy_from_slice(&hash);
                result
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
            Self::HmacSha256(ref hmac) => {
                let mut hmac = hmac.clone();
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
    HmacSha256tr128(AuthHmacSha256tr128),
    HmacSha1tr96(AuthHmacSha1tr96),
}

impl Auth {
    fn init(transform_type: Option<message::TransformType>, key: &[u8]) -> Result<Auth, InitError> {
        match transform_type {
            Some(message::TransformType::AUTH_HMAC_SHA2_256_128) => {
                let key = HmacSha256::new_from_slice(key).map_err(|err| {
                    debug!("Failed to init SHA256-128 HMAC key: {}", err);
                    InitError::new("Failed to init SHA256-128 HMAC key")
                })?;
                Ok(Self::HmacSha256tr128(AuthHmacSha256tr128 { key }))
            }
            Some(message::TransformType::AUTH_HMAC_SHA1_96) => {
                let key = HmacSha1::new_from_slice(key).map_err(|err| {
                    debug!("Failed to init SHA1-96 HMAC key: {}", err);
                    InitError::new("Failed to init SHA1-96 HMAC key")
                })?;
                Ok(Self::HmacSha1tr96(AuthHmacSha1tr96 { key }))
            }
            None => Ok(Self::None),
            _ => Err("Unsupported PRF".into()),
        }
    }

    pub fn sign(&self, data: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::HmacSha256tr128(ref auth) => auth.sign(data),
            Self::HmacSha1tr96(ref auth) => auth.sign(data),
            Self::None => Ok(()),
        }
    }

    pub fn validate(&self, data: &[u8]) -> bool {
        match self {
            Self::HmacSha256tr128(ref auth) => auth.validate(data),
            Self::HmacSha1tr96(ref auth) => auth.validate(data),
            Self::None => true,
        }
    }

    pub fn signature_length(&self) -> usize {
        match self {
            Self::HmacSha256tr128(ref auth) => auth.signature_length(),
            Self::HmacSha1tr96(ref auth) => auth.signature_length(),
            Self::None => 0,
        }
    }
}

struct AuthHmacSha256tr128 {
    key: HmacSha256,
}

impl AuthHmacSha256tr128 {
    pub fn sign(&self, data: &mut [u8]) -> Result<(), CryptoError> {
        let signature_length = self.signature_length();
        if data.len() < signature_length {
            return Err("Not enough space to add signature".into());
        }
        let data_length = data.len() - signature_length;
        let hash = {
            let sign_data = &data[..data_length];
            let mut hmac = self.key.clone();
            hmac.update(sign_data);
            hmac.finalize().into_bytes()
        };
        let dest = &mut data[data_length..];
        dest.copy_from_slice(&hash[..signature_length]);
        Ok(())
    }

    pub fn validate(&self, data: &[u8]) -> bool {
        let signature_length = self.signature_length();
        if data.len() < signature_length {
            return false;
        }
        let received_signature = &data[data.len() - signature_length..];
        let data = &data[..data.len() - signature_length];
        let mut hmac = self.key.clone();
        hmac.update(data);
        let hash = hmac.finalize().into_bytes();
        &hash[..signature_length] == received_signature
    }

    pub fn signature_length(&self) -> usize {
        128 / 8
    }
}

struct AuthHmacSha1tr96 {
    key: HmacSha1,
}

impl AuthHmacSha1tr96 {
    pub fn sign(&self, data: &mut [u8]) -> Result<(), CryptoError> {
        let signature_length = self.signature_length();
        if data.len() < signature_length {
            return Err("Not enough space to add signature".into());
        }
        let data_length = data.len() - signature_length;
        let hash = {
            let sign_data = &data[..data_length];
            let mut hmac = self.key.clone();
            hmac.update(sign_data);
            hmac.finalize().into_bytes()
        };
        let dest = &mut data[data_length..];
        dest.copy_from_slice(&hash[..signature_length]);
        Ok(())
    }

    pub fn validate(&self, data: &[u8]) -> bool {
        let signature_length = self.signature_length();
        if data.len() < signature_length {
            return false;
        }
        let received_signature = &data[data.len() - signature_length..];
        let data = &data[..data.len() - signature_length];
        let mut hmac = self.key.clone();
        hmac.update(data);
        let hash = hmac.finalize().into_bytes();
        &hash[..signature_length] == received_signature
    }

    pub fn signature_length(&self) -> usize {
        96 / 8
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

    pub fn encrypt_data(
        &self,
        data: &mut [u8],
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
            decrypted_slice
        };
        Ok(decrypted_slice)
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

pub trait Encryption {
    fn encrypt(
        &self,
        data: &mut [u8],
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
                let cipher = aes::cipher::KeyInit::new_from_slice(key)
                    .map_err(|_| InitError::new("Failed to init AES CBC 256 cipher"))?;
                Ok(Self::AesCbc256(EncryptionAesCbc256 { cipher }))
            }
            message::TransformType::ENCR_AES_GCM_16 => {
                if transform_type.key_length != Some(256) {
                    return Err("Unsupported key length".into());
                }
                let cipher = aes_gcm::KeyInit::new_from_slice(&key[..32])
                    .map_err(|_| InitError::new("Failed to init AES GCM 256 cipher"))?;
                let mut salt = [0u8; 4];
                salt.copy_from_slice(&key[32..]);
                Ok(Self::AesGcm256(EncryptionAesGcm256 { cipher, salt }))
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

    fn encrypt(
        &self,
        data: &mut [u8],
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

type AesCbc256Decryptor = cbc::Decryptor<Aes256>;
type AesCbc256Encryptor = cbc::Encryptor<Aes256>;

pub struct EncryptionAesCbc256 {
    cipher: Aes256,
}

impl Encryption for EncryptionAesCbc256 {
    fn encrypt<'a>(&self, data: &'a mut [u8], msg_len: usize, _: &[u8]) -> Result<(), CryptoError> {
        let iv_size = AesCbc256Encryptor::iv_size();
        let encrypted_payload_length = self.encrypted_payload_length(msg_len);
        if data.len() < encrypted_payload_length {
            return Err("Message length is too short".into());
        }
        let mut iv = Iv::<AesCbc256Encryptor>::default();
        // Move message to the right to make space for the IV.
        data.copy_within(..msg_len, iv_size);
        let padded_msg_len = encrypted_payload_length - iv_size;
        data[encrypted_payload_length - 1] = (padded_msg_len - 1 - msg_len) as u8;
        rand::thread_rng()
            .try_fill(iv.as_mut_slice())
            .map_err(|err| {
                debug!("Failed to generate IV for AES CBC 256: {}", err);
                "Failed to generate IV for AES CBC 256"
            })?;
        data[..iv_size].copy_from_slice(iv.as_slice());
        let block_encryptor = AesCbc256Encryptor::inner_iv_init(self.cipher.clone(), &iv);
        let data_range = &mut data[iv_size..encrypted_payload_length];
        block_encryptor
            .encrypt_padded_mut::<block_padding::NoPadding>(data_range, padded_msg_len)
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
        let iv_size = AesCbc256Decryptor::iv_size();
        if msg_len <= iv_size {
            return Err("Message length is too short".into());
        }
        let block_decryptor =
            match AesCbc256Decryptor::inner_iv_slice_init(self.cipher.clone(), &data[..iv_size]) {
                Ok(dec) => dec,
                Err(err) => {
                    debug!("Failed to init AES CBC 256 IV: {}", err);
                    return Err("Failed to init AES CBC 256 IV".into());
                }
            };
        let data_range = &mut data[iv_size..msg_len];
        match block_decryptor.decrypt_padded_mut::<block_padding::NoPadding>(data_range) {
            Ok(data) => Ok(data),
            Err(err) => {
                debug!("Failed to decode AES CBC 256 message: {}", err);
                return Err("Failed to decode AES CBC 256 message".into());
            }
        }
    }

    fn encrypted_payload_length(&self, msg_len: usize) -> usize {
        let iv_size = AesCbc256Encryptor::iv_size();
        let block_size = AesCbc256Encryptor::block_size();
        let encrypted_size = (1 + msg_len / block_size) * block_size;
        iv_size + encrypted_size
    }
}

pub struct EncryptionAesGcm256 {
    cipher: Aes256Gcm,
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
        let mut buffer = SliceBuffer {
            slice: &mut data[8..],
            len: msg_len,
        };
        let mut cipher = self.cipher.clone();
        cipher
            .encrypt_in_place(
                Nonce::from_slice(nonce.as_slice()),
                associated_data,
                &mut buffer,
            )
            .map_err(|err| {
                debug!("Failed to encode AES GCM 16 256 message: {}", err);
                "Failed to encode AES GCM 16 256 message"
            })?;
        Ok(())
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
        let mut buffer = SliceBuffer {
            slice: &mut data[8..],
            len: msg_len - 8,
        };
        let mut cipher = self.cipher.clone();
        match cipher.decrypt_in_place(
            Nonce::from_slice(nonce.as_slice()),
            associated_data,
            &mut buffer,
        ) {
            Ok(()) => Ok(&buffer.slice[..buffer.len]),
            Err(err) => {
                debug!("Failed to decode AES GCM 16 256 message: {}", err);
                return Err("Failed to decode AES GCM 16 256 message".into());
            }
        }
    }

    fn encrypted_payload_length(&self, msg_len: usize) -> usize {
        const TAG_SIZE: usize = 16;
        // AES GCM is a stream cipher, encrypted payload will contain
        // IV + message (with padding=1) + tag.
        8 + msg_len + 1 + TAG_SIZE
    }
}

pub fn hash_sha1(data: &[u8]) -> [u8; 160 / 8] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
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

const DH_MODP_GENERATOR_1024: U1024 = U1024::from_u8(2);
const DH_MODP_RESIDUE_1024: constant_mod::Residue<DHModulus1024, { U1024::LIMBS }> =
    const_residue!(DH_MODP_GENERATOR_1024, DHModulus1024);

impl_modulus!(
    DHModulus1024,
    U1024,
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
);
