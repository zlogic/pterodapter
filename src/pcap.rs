use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::{fs::File, io::AsyncWriteExt as _, sync::mpsc};

const SNAPSHOT_LENGTH: usize = 1500;
const QUEUE_LIMIT: usize = 100;

pub struct PcapWriter {
    file: File,
    tx: mpsc::Sender<PcapPacket>,
    rx: mpsc::Receiver<PcapPacket>,
}

impl PcapWriter {
    pub async fn new(path: String) -> Result<PcapWriter, io::Error> {
        let mut file = File::create(path).await?;

        // PCAP file header, indicating the file contains raw IP packets.
        file.write_u32(0xA1B23C4D).await?;
        file.write_u16(2).await?;
        file.write_u16(4).await?;
        file.write_u32(0).await?;
        file.write_u32(0).await?;
        file.write_u32(SNAPSHOT_LENGTH as u32).await?;
        file.write_u16(0).await?;
        file.write_u16(101).await?;

        let (tx, rx) = mpsc::channel(QUEUE_LIMIT);
        Ok(PcapWriter { file, tx, rx })
    }

    pub fn create_sender(&self) -> PcapSender {
        PcapSender {
            tx: self.tx.clone(),
            data_lost: false,
        }
    }

    pub async fn run(mut self) {
        while let Some((packet, length)) = self.rx.recv().await {
            if let Err(err) = self.file.write_all(&packet[0..length]).await {
                log::error!("Failed to write packet to PCAP file: {err}");
            }
        }
        if let Err(err) = self.file.flush().await {
            log::error!("Failed to flush PCAP file: {err}");
        }
    }
}

type PcapPacket = (Box<[u8; 16 + SNAPSHOT_LENGTH]>, usize);

#[derive(Clone)]
pub struct PcapSender {
    tx: mpsc::Sender<PcapPacket>,
    data_lost: bool,
}

impl PcapSender {
    pub fn send_packet(&mut self, packet: &[u8]) {
        if packet.is_empty() {
            return;
        }
        // TODO PCAP: try to reuse/recycle buffers?
        let time = SystemTime::now();

        let time = match time.duration_since(UNIX_EPOCH) {
            Ok(time) => time,
            Err(err) => {
                log::warn!("Failed to convert time into UNIX for PCAP: {err}");
                return;
            }
        };
        let mut data = Box::new([0u8; 16 + SNAPSHOT_LENGTH]);
        data[0..4].copy_from_slice(&(time.as_secs() as u32).to_be_bytes());
        data[4..8].copy_from_slice(&(time.subsec_nanos()).to_be_bytes());
        let captured_length = packet.len().min(SNAPSHOT_LENGTH);
        data[8..12].copy_from_slice(&(captured_length as u32).to_be_bytes());
        data[12..16].copy_from_slice(&(packet.len() as u32).to_be_bytes());
        data[16..16 + captured_length].copy_from_slice(&packet[0..captured_length]);

        if let Err(err) = self.tx.try_send((data, 16 + captured_length)) {
            if !self.data_lost {
                self.data_lost = true;
                log::error!("PCAP send buffer is full, some data will be lost: {err}");
            }
        }
    }
}
