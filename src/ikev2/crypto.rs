use std::{error, fmt};

use super::message;

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
