use common::{tracing, tracing_subscriber};

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
        if field.name() == "message" {
            self.result = write!(self.writer, "{val}");
        } else {
            self.result = write!(self.writer, "{}={val}", field.name());
        }
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
