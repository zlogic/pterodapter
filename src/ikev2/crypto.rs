use crypto_bigint::{
    modular::constant_mod::{self, ResidueParams},
    Encoding,
};
use hmac::{Hmac, Mac};
use log::debug;
use p256::{elliptic_curve::sec1::Tag, EncodedPoint, NonZeroScalar, ProjectivePoint, PublicKey};
use sha2::Sha256;
use std::{error, fmt};

use crypto_bigint::{const_residue, impl_modulus, rand_core::OsRng, Random, U1024};

use super::message;

const MAX_DH_KEY_LENGTH: usize = 128;
const MAX_PRF_KEY_LENGTH: usize = 32;

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
    pub fn create_dh(&self) -> Option<DHTransform> {
        DHTransform::init(self.dh.as_ref()?.transform_type)
    }

    pub fn create_prf(&self, key: &[u8]) -> Option<PseudorandomTransform> {
        PseudorandomTransform::init(self.prf.as_ref()?.transform_type, key)
    }

    pub fn protocol_id(&self) -> message::IPSecProtocolID {
        self.protocol_id
    }

    pub fn spi(&self) -> message::SPI {
        self.spi
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
                    message::TransformType::ENCR_AES_CBC => parameters.enc = Some(transform),
                    message::TransformType::DH_256_ECP => parameters.dh = Some(transform),
                    // Valid Windows options.
                    message::TransformType::ENCR_AES_GCM_16 => parameters.enc = Some(transform),
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
    fn init(transform_type: message::TransformType) -> Option<DHTransform> {
        let (_, dh_group) = transform_type.type_id();
        match transform_type {
            message::TransformType::DH_1024_MODP => {
                let private_key = U1024::random(&mut OsRng);
                // This calculates DH_MODP_GENERATOR_1024^private_key mod DHModulus1024.
                let public_key = DH_MODP_RESIDUE_1024.pow(&private_key).retrieve();
                Some(DHTransform::MODP1024(dh_group, private_key, public_key))
            }
            message::TransformType::DH_256_ECP => {
                let private_key = NonZeroScalar::random(&mut OsRng);
                let public_key = PublicKey::from_secret_scalar(&private_key);
                Some(DHTransform::ECP256(dh_group, private_key, public_key))
            }
            _ => None,
        }
    }

    pub fn read_public_key(&self) -> Array<MAX_DH_KEY_LENGTH> {
        let mut res = Array::new(self.key_length_bytes());
        match self {
            Self::MODP1024(_, _, public_key) => {
                res.as_mut_slice()
                    .copy_from_slice(&public_key.to_be_bytes());
            }
            Self::ECP256(_, _, public_key) => res
                .as_mut_slice()
                .copy_from_slice(&EncodedPoint::from(public_key).as_bytes()[1..]),
        }
        res
    }

    pub fn key_length_bytes(&self) -> usize {
        match self {
            Self::MODP1024(_, _, _) => 128,
            Self::ECP256(_, _, _) => 64,
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
    ) -> Option<[u8; MAX_DH_KEY_LENGTH]> {
        let mut res = [0u8; MAX_DH_KEY_LENGTH];
        let dest = &mut res[0..self.key_length_bytes()];
        match self {
            Self::MODP1024(_, private_key, _) => {
                let other_public_key = U1024::from_be_slice(other_public_key);
                let other_key_residue = const_residue!(other_public_key, DHModulus1024);
                let shared_key = other_key_residue.pow(&private_key).retrieve();
                dest.copy_from_slice(&shared_key.to_be_bytes());
            }
            Self::ECP256(_, private_key, _) => {
                let mut other_public_key_sec1 = [0u8; 65];
                other_public_key_sec1[0] = Tag::Uncompressed.into();
                other_public_key_sec1[1..].copy_from_slice(other_public_key);
                let other_public_key = match PublicKey::from_sec1_bytes(&other_public_key_sec1) {
                    Ok(key) => key,
                    Err(err) => {
                        debug!("Failed to decode other public key {}", err);
                        return None;
                    }
                };
                let public_point = ProjectivePoint::from(other_public_key.as_affine());
                let secret_point = (&public_point * private_key).to_affine();
                dest.copy_from_slice(&EncodedPoint::from(secret_point).as_bytes()[1..]);
            }
        }
        Some(res)
    }
}

type HmacSha256 = Hmac<Sha256>;

pub enum PseudorandomTransform {
    HmacSha256(HmacSha256),
}

impl PseudorandomTransform {
    fn init(transform_type: message::TransformType, key: &[u8]) -> Option<PseudorandomTransform> {
        match transform_type {
            message::TransformType::PRF_HMAC_SHA2_256 => {
                let hmac = HmacSha256::new_from_slice(key).ok()?;
                Some(Self::HmacSha256(hmac))
            }
            _ => None,
        }
    }

    pub fn prf(&mut self, data: &[u8]) -> Array<MAX_PRF_KEY_LENGTH> {
        match self {
            Self::HmacSha256(ref mut hmac) => {
                hmac.update(data);
                let hash = hmac.finalize_reset().into_bytes();
                let mut result = Array::new(32);
                result.as_mut_slice().copy_from_slice(&hash);
                result
            }
        }
    }

    fn generate_key_material(&mut self) {}
}

const DH_MODP_GENERATOR_1024: U1024 = U1024::from_u8(2);
const DH_MODP_RESIDUE_1024: constant_mod::Residue<DHModulus1024, { U1024::LIMBS }> =
    const_residue!(DH_MODP_GENERATOR_1024, DHModulus1024);

impl_modulus!(
    DHModulus1024,
    U1024,
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
);
