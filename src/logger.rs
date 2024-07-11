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
