use log::{Level, Log, Metadata, Record};

static LOGGER: Logger = Logger {};

pub fn setup_logger() -> Result<(), log::SetLoggerError> {
    log::set_logger(&LOGGER)?;
    // TODO: allow to set the logging level.
    log::set_max_level(log::LevelFilter::Trace);
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
