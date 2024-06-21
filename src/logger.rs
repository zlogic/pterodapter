use log::{Level, Log, Metadata, Record};

static LOGGER: Logger = Logger {};

pub fn setup_logger() -> Result<(), log::SetLoggerError> {
    const DEFAULT_LEVEL: log::LevelFilter = log::LevelFilter::Info;
    log::set_logger(&LOGGER)?;
    let max_level = std::env::var("RUST_LOG")
        .map(|level| match level.to_uppercase().as_str() {
            "TRACE" => log::LevelFilter::Trace,
            "DEBUG" => log::LevelFilter::Debug,
            "INFO" => log::LevelFilter::Info,
            "WARN" => log::LevelFilter::Warn,
            "ERROR" => log::LevelFilter::Error,
            "OFF" => log::LevelFilter::Off,
            &_ => DEFAULT_LEVEL,
        })
        .unwrap_or(DEFAULT_LEVEL);
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
