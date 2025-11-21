use std::time::Duration;

// Semantics:
// Maximum number of buffered handshake requests
// (either from outside message or handshake requests triggered locally)
pub const MAX_QUEUED_INCOMING_HANDSHAKES: usize = 4096;

// Semantics:
// When the number of queued handshake requests exceeds this number
// the device is considered under load and DoS mitigation is triggered.
pub const THRESHOLD_UNDER_LOAD: usize = MAX_QUEUED_INCOMING_HANDSHAKES / 8;

// Semantics:
// When a device is detected to go under load,
// it will remain under load for at least the following duration.
pub const DURATION_UNDER_LOAD: Duration = Duration::from_secs(1);

// Semantics:
// The payload of transport messages are padded to this multiple
pub const MESSAGE_PADDING_MULTIPLE: usize = 16;
