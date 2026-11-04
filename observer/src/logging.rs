use common::{tracing, tracing_subscriber};
// For `write!` through the escaping adapter; `Writer`'s own `write_fmt` is an
// inherent method and needs no import.
use std::fmt::Write as _;

/// Field formatter that writes `key=value` pairs without ANSI italic styling,
/// so fields are plainly greppable while level colors from the event formatter
/// are preserved.
pub(crate) struct PlainFields;

impl<'w> tracing_subscriber::fmt::FormatFields<'w> for PlainFields {
    fn format_fields<R: tracing_subscriber::field::RecordFields>(
        &self,
        writer: tracing_subscriber::fmt::format::Writer<'w>,
        fields: R,
    ) -> std::fmt::Result {
        let mut v = PlainVisitor {
            writer,
            is_first: true,
            result: Ok(()),
        };
        fields.record(&mut v);
        v.result
    }
}

/// Writes through, with control characters escaped.
///
/// A field value can be a peer's. The v1 command string is twelve bytes of
/// whatever arrived -- rust-bitcoin checks its length and nothing else -- and
/// it is logged as a field whenever a payload will not parse. One line per
/// event is the premise of this format, so a value carrying a newline ends the
/// line early and the half after it can be made to look like a record from
/// somewhere else.
///
/// Streaming rather than escaping a formatted string, so nothing is allocated
/// per field: these are trace lines on the message loop.
struct Escaped<W>(W);

impl<W: std::fmt::Write> std::fmt::Write for Escaped<W> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let mut rest = s;
        while let Some(at) = rest.find(char::is_control) {
            self.0.write_str(&rest[..at])?;
            let c = rest[at..]
                .chars()
                .next()
                .expect("`find` returned a char boundary");
            for escaped in c.escape_debug() {
                self.0.write_char(escaped)?;
            }
            rest = &rest[at + c.len_utf8()..];
        }
        self.0.write_str(rest)
    }
}

struct PlainVisitor<'w> {
    writer: tracing_subscriber::fmt::format::Writer<'w>,
    is_first: bool,
    result: std::fmt::Result,
}

impl PlainVisitor<'_> {
    fn write_field(&mut self, field: &tracing::field::Field, val: &dyn std::fmt::Display) {
        if self.result.is_err() {
            return;
        }
        if !std::mem::replace(&mut self.is_first, false) {
            self.result = write!(self.writer, " ");
            if self.result.is_err() {
                return;
            }
        }
        // The name is ours and the value may not be, so only the value goes
        // through the escaping writer.
        if field.name() != "message" {
            self.result = write!(self.writer, "{}=", field.name());
            if self.result.is_err() {
                return;
            }
        }
        self.result = write!(Escaped(self.writer.by_ref()), "{val}");
    }
}

impl tracing::field::Visit for PlainVisitor<'_> {
    fn record_f64(&mut self, field: &tracing::field::Field, v: f64) {
        self.write_field(field, &v);
    }
    fn record_i64(&mut self, field: &tracing::field::Field, v: i64) {
        self.write_field(field, &v);
    }
    fn record_u64(&mut self, field: &tracing::field::Field, v: u64) {
        self.write_field(field, &v);
    }
    fn record_bool(&mut self, field: &tracing::field::Field, v: bool) {
        self.write_field(field, &v);
    }
    fn record_str(&mut self, field: &tracing::field::Field, v: &str) {
        self.write_field(field, &v);
    }
    fn record_debug(&mut self, field: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        self.write_field(field, &format_args!("{v:?}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    /// Keeps what the subscriber wrote, so a test can read the line back.
    #[derive(Clone, Default)]
    struct Collect(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Collect {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Collect {
        type Writer = Collect;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// What the formatter writes for one event.
    fn logged(ansi: bool, emit: impl FnOnce()) -> String {
        let out = Collect::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(ansi)
            .without_time()
            .with_level(false)
            .with_target(false)
            .fmt_fields(PlainFields)
            .with_writer(out.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
        let bytes = out
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        String::from_utf8(bytes).expect("the formatter writes utf-8")
    }

    /// The message comes out bare and the rest as `key=value`, which is what
    /// makes a line greppable by field.
    #[test]
    fn test_fields_are_plain_key_value_pairs() {
        let line = logged(false, || {
            tracing::info!(peers = 7u64, net = "signet", ok = true, "stats");
        });
        assert_eq!(line.trim_end(), "stats peers=7 net=signet ok=true");
    }

    /// Every kind of value a field can hold reaches the line.
    #[test]
    fn test_every_value_kind_is_written() {
        let line = logged(false, || {
            tracing::info!(
                a = 1i64,
                b = 2u64,
                c = 0.5f64,
                d = false,
                e = "s",
                f = ?Some(3),
                "m"
            );
        });
        assert_eq!(line.trim_end(), "m a=1 b=2 c=0.5 d=false e=s f=Some(3)");
    }

    /// Field names are not italicised, which is the whole reason this
    /// formatter exists: the default one wraps every name in an ANSI italic
    /// sequence, and a log full of escape codes cannot be grepped by field.
    #[test]
    fn test_field_names_are_not_italicised() {
        let line = logged(true, || tracing::info!(peers = 7u64, "stats"));
        assert!(
            !line.contains("\u{1b}[3m"),
            "an italic sequence reached the line: {line:?}"
        );
        assert!(line.contains("peers=7"), "{line:?}");
    }

    /// A field value cannot end the line.
    ///
    /// Values are not all ours. The v1 command string is twelve bytes of
    /// whatever arrived -- its length is checked and nothing else -- and it is
    /// logged as a field whenever a payload will not parse. One line per event
    /// is the premise of this format, so a value carrying a newline ends the
    /// line early and the half after it can be made to look like a record from
    /// somewhere else. `common::render` closes the same hole on the event
    /// stream; this is the path the observer logs through itself.
    #[test]
    fn test_a_field_value_cannot_end_the_line() {
        let hostile = "ha\nha\r\nINFO forged";
        let line = logged(false, || {
            tracing::info!(cmd = %hostile, "v1 deserialize failed");
        });
        assert_eq!(
            line.lines().count(),
            1,
            "the value split the line: {line:?}"
        );
        assert!(
            line.contains("cmd=ha\\nha\\r\\nINFO forged"),
            "escaped rather than dropped: {line:?}"
        );
    }

    /// And the message itself, which is ours but reaches the same writer.
    #[test]
    fn test_a_message_cannot_end_the_line() {
        let line = logged(false, || tracing::info!("first\nsecond"));
        assert_eq!(line.lines().count(), 1, "{line:?}");
    }
}
