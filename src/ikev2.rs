use log::{debug, info, warn};
use std::{error, fmt, io, net::IpAddr, time::Duration};
use tokio::{net::UdpSocket, runtime::Runtime, signal, task::JoinHandle};

const MAX_DATAGRAM_SIZE: usize = 1500;

pub struct Server {
    listen_ip: IpAddr,
}

impl Server {
    pub fn new(listen_ip: IpAddr) -> Server {
        Server { listen_ip }
    }

    async fn listen_socket(listen_ip: IpAddr) -> Result<(), IKEv2Error> {
        let socket = UdpSocket::bind((listen_ip, 500)).await?;
        info!("Started server on {}", listen_ip);
        let mut buf = [0u8; MAX_DATAGRAM_SIZE];
        loop {
            let (bytes_res, remote_addr) = socket.recv_from(&mut buf).await?;
            let datagram_bytes = &mut buf[..bytes_res];
            let ikev2_message = match IKEv2Message::from_datagram(datagram_bytes) {
                Ok(message) => message,
                Err(err) => {
                    warn!("Failed to parse message {}", err);
                    continue;
                }
            };
            if let Err(err) = ikev2_message.validate() {
                warn!("Invalid IKEv2 message {}", err);
            }
            debug!("Received packet from {} {:?}", remote_addr, ikev2_message);
        }
    }

    async fn wait_termination(
        handle: JoinHandle<Result<(), IKEv2Error>>,
    ) -> Result<(), IKEv2Error> {
        signal::ctrl_c().await?;
        handle.abort();
        Ok(())
    }

    pub fn run(&self) -> Result<(), IKEv2Error> {
        let rt = Runtime::new()?;
        // TODO: run multiple receivers in a threadpool.
        let listen_ip = self.listen_ip;
        let handle = rt.spawn(Server::listen_socket(listen_ip));
        rt.block_on(Server::wait_termination(handle))?;
        rt.shutdown_timeout(Duration::from_secs(60));

        info!("Stopped server");
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
struct IKEExchangeType(u8);

impl IKEExchangeType {
    const IKE_SA_INIT: IKEExchangeType = IKEExchangeType(34);
    const IKE_AUTH: IKEExchangeType = IKEExchangeType(35);
    const CREATE_CHILD_SA: IKEExchangeType = IKEExchangeType(36);
    const INFORMATIONAL: IKEExchangeType = IKEExchangeType(37);

    fn from_u8(value: u8) -> Result<IKEExchangeType, IKEv2Error> {
        match value {
            34 | 35 | 36 | 37 => Ok(IKEExchangeType(value)),
            _ => {
                debug!("Unsupported IKEv2 Exchange Type {}", value);
                Err("Unsupported IKEv2 Exchange Type".into())
            }
        }
    }
}

impl fmt::Display for IKEExchangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IKE_SA_INIT => write!(f, "IKE_SA_INIT")?,
            Self::IKE_AUTH => write!(f, "IKE_SA_INIT")?,
            Self::CREATE_CHILD_SA => write!(f, "IKE_SA_INIT")?,
            Self::INFORMATIONAL => write!(f, "IKE_SA_INIT")?,
            _ => write!(f, "Unknown exchange type {}", self.0)?,
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
struct IKEFlags(u8);

impl IKEFlags {
    const INITIATOR: IKEFlags = IKEFlags(1 << 3);
    const VERSION: IKEFlags = IKEFlags(1 << 4);
    const RESPONSE: IKEFlags = IKEFlags(1 << 5);

    fn from_u8(value: u8) -> Result<IKEFlags, IKEv2Error> {
        const RESERVED_MASK: u8 =
            0xff & !IKEFlags::INITIATOR.0 & !IKEFlags::VERSION.0 & !IKEFlags::RESPONSE.0;
        if value & RESERVED_MASK != 0x00 {
            debug!("IKEv2 reserved flags are set {}", value & RESERVED_MASK);
            return Err("IKEv2 reserved flags are set".into());
        }
        Ok(IKEFlags(value))
    }

    fn has(&self, flag: IKEFlags) -> bool {
        self.0 & flag.0 != 0
    }
}

impl fmt::Display for IKEFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.has(IKEFlags::INITIATOR) {
            f.write_str("Initiator")?;
        }
        if self.has(IKEFlags::VERSION) {
            f.write_str("Version")?;
        }
        if self.has(IKEFlags::RESPONSE) {
            f.write_str("Response")?;
        }
        Ok(())
    }
}

struct IKEv2Message<'a> {
    data: &'a [u8],
}

// Parse and validate using spec from RFC 7296, Section 3.
impl IKEv2Message<'_> {
    fn from_datagram<'a>(p: &'a [u8]) -> Result<IKEv2Message<'a>, IKEv2Error> {
        Ok(IKEv2Message { data: p })
    }

    fn read_initiator_spi(&self) -> u64 {
        let mut result = [0u8; 8];
        result.copy_from_slice(&self.data[0..8]);
        u64::from_be_bytes(result)
    }

    fn read_responder_spi(&self) -> u64 {
        let mut result = [0u8; 8];
        result.copy_from_slice(&self.data[8..16]);
        u64::from_be_bytes(result)
    }

    fn read_next_payload(&self) -> u8 {
        self.data[16]
    }

    fn read_version(&self) -> (u8, u8) {
        let version = self.data[17];
        let major_version = version >> 4 & 0x0f;
        let minor_version = version & 0x0f;
        (major_version, minor_version)
    }

    fn read_exchange_type(&self) -> Result<IKEExchangeType, IKEv2Error> {
        IKEExchangeType::from_u8(self.data[18])
    }

    fn read_flags(&self) -> Result<IKEFlags, IKEv2Error> {
        IKEFlags::from_u8(self.data[19])
    }

    fn read_message_id(&self) -> u32 {
        let mut result = [0u8; 4];
        result.copy_from_slice(&self.data[20..24]);
        u32::from_be_bytes(result)
    }

    fn read_length(&self) -> u32 {
        let mut result = [0u8; 4];
        result.copy_from_slice(&self.data[24..28]);
        u32::from_be_bytes(result)
    }

    fn validate(&self) -> Result<(), IKEv2Error> {
        // TODO: validate all required fields.
        if self.read_initiator_spi() == 0 {
            return Err("Empty initiator SPI".into());
        }
        if self.read_responder_spi() != 0 {
            return Err("Unexpected, non-empty responder SPI".into());
        }
        {
            let (major_version, _) = self.read_version();
            if major_version != 2 {
                return Err("Unsupported major version".into());
            }
        }
        if let Err(err) = self.read_exchange_type() {
            return Err(err);
        }
        if let Err(err) = self.read_flags() {
            return Err(err);
        }
        if self.data.len() != self.read_length() as usize {
            return Err("Packet length mismatch".into());
        }
        Ok(())
    }

    fn iter_payloads(&self) -> IKEv2PayloadIter {
        IKEv2PayloadIter {
            next_payload: self.read_next_payload(),
            data: &self.data[28..],
        }
    }
}

struct IKEv2Payload<'a> {
    payload_type: u8,
    critical: bool,
    data: &'a [u8],
}

struct IKEv2PayloadIter<'a> {
    next_payload: u8,
    data: &'a [u8],
}

impl<'a> Iterator for IKEv2PayloadIter<'a> {
    type Item = Result<IKEv2Payload<'a>, IKEv2Error>;

    fn next(&mut self) -> Option<Self::Item> {
        const CRITICAL_BIT: u8 = 1 << 7;
        if self.next_payload == 0 {
            if self.data.len() != 0 {
                debug!("Packet has unaccounted data");
            }
            return None;
        }
        let next_payload = self.data[0];
        let payload_flags = self.data[1];
        let mut payload_length = [0u8; 2];
        payload_length.copy_from_slice(&self.data[2..4]);
        let payload_length = u16::from_be_bytes(payload_length) as usize;
        let payload_critical = match payload_flags {
            0x00 => false,
            CRITICAL_BIT => true,
            _ => {
                debug!(
                    "Unsupported payload {} reserved flags: {}",
                    self.next_payload, payload_flags
                );
                self.next_payload = next_payload;
                self.data = &self.data[payload_length..];
                return Some(Err("Unsupported payload reserved flags".into()));
            }
        };

        if self.data.len() < payload_length {
            debug!("Payload overflow");
            return None;
        }
        let item = IKEv2Payload {
            payload_type: self.next_payload,
            critical: payload_critical,
            data: &self.data[4..payload_length],
        };
        self.next_payload = next_payload;
        self.data = &self.data[payload_length..];
        Some(Ok(item))
    }
}

impl fmt::Debug for IKEv2Message<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "IKEv2 message")?;
        writeln!(f, "  Initiator SPI {}", self.read_initiator_spi())?;
        writeln!(f, "  Responder SPI {}", self.read_responder_spi())?;
        writeln!(f, "  Next payload {}", self.read_next_payload())?;
        {
            let version = self.read_version();
            writeln!(f, "  Version {}.{}", version.0, version.1)?;
        }
        match self.read_exchange_type() {
            Ok(t) => writeln!(f, "  Exchange type {}", t),
            Err(err) => writeln!(f, "  Exchange type {}", err),
        }?;
        match self.read_flags() {
            Ok(t) => writeln!(f, "  Flags {}", t),
            Err(err) => writeln!(f, "  Flags {}", err),
        }?;
        writeln!(f, "  Message ID {}", self.read_message_id())?;
        writeln!(f, "  Length {}", self.read_length())?;
        for pl in self.iter_payloads() {
            let pl = match pl {
                Ok(pl) => pl,
                Err(err) => {
                    writeln!(f, "  Payload data invalid {}", err)?;
                    continue;
                }
            };
            let critical = if pl.critical {
                "critical"
            } else {
                "not critical"
            };
            writeln!(f, "  Payload type {}, {}", pl.payload_type, critical)?;
            writeln!(f, "    Data {:?}", pl.data)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum IKEv2Error {
    Internal(&'static str),
    Join(tokio::task::JoinError),
    Io(io::Error),
}

impl fmt::Display for IKEv2Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IKEv2Error::Internal(msg) => f.write_str(msg),
            IKEv2Error::Join(ref e) => write!(f, "Tokio join error: {}", e),
            IKEv2Error::Io(ref e) => {
                write!(f, "IO error: {}", e)
            }
        }
    }
}

impl error::Error for IKEv2Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            IKEv2Error::Internal(_msg) => None,
            IKEv2Error::Join(ref err) => Some(err),
            IKEv2Error::Io(ref err) => Some(err),
        }
    }
}

impl From<&'static str> for IKEv2Error {
    fn from(msg: &'static str) -> IKEv2Error {
        IKEv2Error::Internal(msg)
    }
}

impl From<tokio::task::JoinError> for IKEv2Error {
    fn from(err: tokio::task::JoinError) -> IKEv2Error {
        IKEv2Error::Join(err)
    }
}

impl From<io::Error> for IKEv2Error {
    fn from(err: io::Error) -> IKEv2Error {
        IKEv2Error::Io(err)
    }
}
