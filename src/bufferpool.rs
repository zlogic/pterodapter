use std::{
    borrow::{Borrow, BorrowMut},
    fmt,
    ops::{Deref, DerefMut},
};

use log::debug;
use tokio::{
    runtime,
    sync::{mpsc, oneshot},
};

pub struct BufferPool {
    capacity: usize,
    buffer_size: usize,
    rx_return: mpsc::Receiver<Vec<u8>>,
    tx_return: mpsc::Sender<Vec<u8>>,
}

impl BufferPool {
    pub fn new(capacity: usize, buffer_size: usize) -> BufferPool {
        let (tx_return, rx_return) = mpsc::channel(capacity);
        BufferPool {
            capacity,
            buffer_size,
            rx_return,
            tx_return,
        }
    }

    pub async fn borrow(&mut self) -> Option<Buffer> {
        let buf = if self.tx_return.strong_count() < self.capacity {
            Vec::with_capacity(self.buffer_size)
        } else {
            self.rx_return.recv().await?
        };
        Some(Buffer::new(buf, self.tx_return.clone()).await)
    }
}

pub struct Buffer {
    buf: Option<Vec<u8>>,
    tx_return: Option<oneshot::Sender<Vec<u8>>>,
}

impl Buffer {
    async fn new(buf: Vec<u8>, tx_pool_return: mpsc::Sender<Vec<u8>>) -> Buffer {
        let (tx_return, rx_return) = oneshot::channel();
        let rt = runtime::Handle::current();
        rt.spawn(async move {
            if let Ok(buf) = rx_return.await {
                if tx_pool_return.send(buf).await.is_err() {
                    debug!("Failed to return used buffer: listener closed");
                }
            } else {
                debug!("Failed to return used buffer: oneshot receiver closed");
            }
        });
        Buffer {
            buf: Some(buf),
            tx_return: Some(tx_return),
        }
    }
}

impl Deref for Buffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        self.buf.as_ref().unwrap()
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf.as_mut().unwrap()
    }
}

impl Borrow<Vec<u8>> for Buffer {
    fn borrow(&self) -> &Vec<u8> {
        self.buf.as_ref().unwrap()
    }
}

impl BorrowMut<Vec<u8>> for Buffer {
    fn borrow_mut(&mut self) -> &mut Vec<u8> {
        self.buf.as_mut().unwrap()
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        let mut buf = self.buf.take().expect("Buffer dropped");
        buf.truncate(0);
        let tx_return = self.tx_return.take().expect("Buffer dropped twice");
        if tx_return.send(buf).is_err() {
            debug!("Failed to return dropped buffer: listener closed");
        }
    }
}

impl fmt::Display for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        if let Some(ref data) = self.buf {
            for (i, b) in data.iter().enumerate() {
                write!(f, "{:02x}", b)?;
                if i + 1 < data.len() {
                    write!(f, " ")?;
                }
            }
            Ok(())
        } else {
            write!(f, "[None]")
        }
    }
}
