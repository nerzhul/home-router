use std::fmt::Write as _;
use std::sync::Mutex;

use syslog::{Facility, Formatter3164, Severity};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::{layer::Context, Layer};

/// A `tracing_subscriber` layer that forwards log events to syslog.
pub struct SyslogLayer {
    logger: Mutex<syslog::Logger<syslog::LoggerBackend, Formatter3164>>,
}

impl SyslogLayer {
    /// Connect to the local syslog socket and build the layer.
    pub fn new() -> anyhow::Result<Self> {
        let formatter = Formatter3164 {
            facility: Facility::LOG_DAEMON,
            hostname: None,
            process: "ndhcpd".to_owned(),
            pid: std::process::id(),
        };
        let logger = syslog::unix(formatter).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(Self {
            logger: Mutex::new(logger),
        })
    }
}

// ── visitor ──────────────────────────────────────────────────────────────────

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            // Display-wrapped values expose Display via their Debug impl.
            write!(self.0, "{value:?}").ok();
        } else {
            write!(self.0, " {}={value:?}", field.name()).ok();
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        } else {
            write!(self.0, " {}={value}", field.name()).ok();
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        write!(self.0, " {}={value}", field.name()).ok();
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        write!(self.0, " {}={value}", field.name()).ok();
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        write!(self.0, " {}={value}", field.name()).ok();
    }
}

// ── Layer impl ────────────────────────────────────────────────────────────────

impl<S: Subscriber> Layer<S> for SyslogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);

        let severity = match *event.metadata().level() {
            Level::ERROR => Severity::LOG_ERR,
            Level::WARN => Severity::LOG_WARNING,
            Level::INFO => Severity::LOG_INFO,
            Level::DEBUG => Severity::LOG_DEBUG,
            Level::TRACE => Severity::LOG_DEBUG,
        };

        if let Ok(mut logger) = self.logger.lock() {
            let msg = &visitor.0;
            let _ = match severity {
                Severity::LOG_ERR => logger.err(msg),
                Severity::LOG_WARNING => logger.warning(msg),
                Severity::LOG_INFO => logger.info(msg),
                _ => logger.debug(msg),
            };
        }
    }
}
