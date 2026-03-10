use std::sync::{Arc, Mutex};

use auths_telemetry::EventSink;
use auths_telemetry::sinks::composite::CompositeSink;
use auths_telemetry::sinks::stdout::WriterSink;

/// Shared buffer for capturing sink output without stdout.
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn make_capturing_sink() -> (Arc<Mutex<Vec<u8>>>, WriterSink<SharedBuf>) {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let sink = WriterSink::new(SharedBuf(Arc::clone(&buf)));
    (buf, sink)
}

fn captured_lines(buf: &Arc<Mutex<Vec<u8>>>) -> Vec<String> {
    let bytes = buf.lock().unwrap().clone();
    String::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

#[test]
fn fan_out_delivers_to_all_children() {
    let (buf_a, sink_a) = make_capturing_sink();
    let (buf_b, sink_b) = make_capturing_sink();
    let composite = CompositeSink::new(vec![Arc::new(sink_a), Arc::new(sink_b)]);

    composite.emit("event-1");
    composite.emit("event-2");

    assert_eq!(captured_lines(&buf_a), vec!["event-1", "event-2"]);
    assert_eq!(captured_lines(&buf_b), vec!["event-1", "event-2"]);
}

#[test]
fn empty_composite_does_not_panic() {
    let composite = CompositeSink::empty();
    composite.emit("payload");
    composite.flush();
}

#[test]
fn panicking_child_does_not_block_siblings() {
    struct PanicSink;
    impl EventSink for PanicSink {
        fn emit(&self, _payload: &str) {
            panic!("intentional test panic");
        }
        fn flush(&self) {}
    }

    let (buf, good_sink) = make_capturing_sink();
    let composite = CompositeSink::new(vec![
        Arc::new(PanicSink) as Arc<dyn EventSink>,
        Arc::new(good_sink),
    ]);

    composite.emit("should-survive");
    assert_eq!(captured_lines(&buf), vec!["should-survive"]);
}

#[test]
fn flush_fans_out_to_all_children() {
    let (buf_a, sink_a) = make_capturing_sink();
    let (buf_b, sink_b) = make_capturing_sink();
    let composite = CompositeSink::new(vec![Arc::new(sink_a), Arc::new(sink_b)]);

    composite.emit("before-flush");
    composite.flush();

    assert_eq!(captured_lines(&buf_a), vec!["before-flush"]);
    assert_eq!(captured_lines(&buf_b), vec!["before-flush"]);
}

#[test]
fn single_child_composite_forwards_correctly() {
    let (buf, sink) = make_capturing_sink();
    let composite = CompositeSink::new(vec![Arc::new(sink)]);

    composite.emit("solo");
    assert_eq!(captured_lines(&buf), vec!["solo"]);
}
