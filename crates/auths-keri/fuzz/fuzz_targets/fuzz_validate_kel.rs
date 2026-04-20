#![no_main]
//! Byte-level KEL replay fuzz target.
//!
//! Feeds attacker-controlled bytes through the `import_cesr_to_events`
//! codec path, then hands the resulting events to `validate_kel` and
//! asserts structural invariants on any `Ok` branch. A structure-
//! aware variant that generates `Event` values via `Arbitrary` can be
//! layered on top of this harness later — the byte-level version
//! subsumes the interesting cases because the codec itself produces
//! well-formed-but-hostile event sequences for most inputs.
//!
//! # Invariants asserted on `Ok`
//!
//! 1. Event list is non-empty (validate_kel requires at least an Icp).
//! 2. Sequence numbers are strictly monotonic across consecutive events.
//! 3. The inception event's `i` (controller AID) is preserved on every
//!    following event.

use auths_keri::{CesrV1Codec, Event, import_cesr_to_events, validate_kel};
use libfuzzer_sys::fuzz_target;

fn sn(e: &Event) -> u128 {
    match e {
        Event::Icp(ev) => ev.s.value(),
        Event::Rot(ev) => ev.s.value(),
        Event::Ixn(ev) => ev.s.value(),
        Event::Dip(ev) => ev.s.value(),
        Event::Drt(ev) => ev.s.value(),
    }
}

fn controller(e: &Event) -> String {
    match e {
        Event::Icp(ev) => ev.i.to_string(),
        Event::Rot(ev) => ev.i.to_string(),
        Event::Ixn(ev) => ev.i.to_string(),
        Event::Dip(ev) => ev.i.to_string(),
        Event::Drt(ev) => ev.i.to_string(),
    }
}

fuzz_target!(|data: &[u8]| {
    let codec = CesrV1Codec;
    let Ok(events) = import_cesr_to_events(&codec, data) else {
        return;
    };
    if events.is_empty() {
        return;
    }
    let Ok(_key_state) = validate_kel(&events) else {
        return;
    };

    // Invariant: strictly monotonic sequence numbers.
    for window in events.windows(2) {
        let a = sn(&window[0]);
        let b = sn(&window[1]);
        if b <= a {
            panic!("validate_kel accepted non-monotonic sn: {a} -> {b}");
        }
    }

    // Invariant: controller AID is preserved across the sequence.
    let i0 = controller(&events[0]);
    for (idx, e) in events.iter().enumerate().skip(1) {
        if controller(e) != i0 {
            panic!("event #{idx} has mismatched controller AID");
        }
    }
});
