use log::{Level, Log, Metadata, Record};

static LOGGER: Logger = Logger {};

pub fn setup_logger(max_level: log::LevelFilter) -> Result<(), log::SetLoggerError> {
    log::set_logger(&LOGGER)?;
    log::set_max_level(max_level);
    Ok(())
}

struct Logger {}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        println!(
            "{} {} -- {}",
            record.level(),
            record.target(),
            record.args()
        );
    }

    fn flush(&self) {}
}

pub fn fmt_slice_hex(data: &[u8]) -> impl std::fmt::Display {
    struct HexSlice<'a>(&'a [u8]);
    impl std::fmt::Display for HexSlice<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for (i, b) in self.0.iter().enumerate() {
                write!(f, "{b:02x}")?;
                if i + 1 < self.0.len() {
                    write!(f, " ")?;
                }
            }
            Ok(())
        }
    }
    HexSlice(data)
}
