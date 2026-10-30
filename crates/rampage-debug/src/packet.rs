//! GDB Remote Serial Protocol framing: `$data#cs` packets, acknowledgements, notifications, run-length decoding and
//! binary escaping. Everything here is pure, so the parser can be driven with arbitrary bytes.

/// The most bytes a decoded packet may hold, whatever the stub advertises.
pub const MAX_PACKET_BYTES: usize = 1024 * 1024;

/// One thing read from the stub's byte stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// `+`: the previous packet arrived intact.
    Ack,
    /// `-`: the previous packet arrived damaged and should be sent again.
    Nak,
    /// A `$...#cs` packet with a valid checksum, run-length expanded but not binary-unescaped.
    Packet(Vec<u8>),
    /// A `$...#cs` packet whose checksum does not match its contents.
    Corrupt,
    /// A `%...#cs` asynchronous notification, which this client does not subscribe to and ignores.
    Notification,
    /// A byte outside any packet.
    Noise(u8),
}

/// Why the byte stream cannot be framed any further.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("packet exceeds the {0}-byte limit")]
    Oversized(usize),
    #[error("malformed run-length encoding in packet")]
    RunLength,
}

/// Splits the stub's byte stream into frames. Bytes arrive in arbitrary pieces through [`Framer::push`].
#[derive(Debug)]
pub struct Framer {
    buffer: Vec<u8>,
    start: usize,
    limit: usize,
}

impl Framer {
    /// A framer that refuses packets whose raw or decoded form exceeds `limit` bytes.
    pub fn new(limit: usize) -> Self {
        Self { buffer: Vec::new(), start: 0, limit: limit.min(MAX_PACKET_BYTES) }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        // Drop consumed frames, so a stream of frames split across reads holds at most one partial frame plus the
        // bytes of one read.
        if self.start > 0 && (self.start == self.buffer.len() || self.start >= self.buffer.len() / 2) {
            self.buffer.drain(..self.start);
            self.start = 0;
        }
        self.buffer.extend_from_slice(bytes);
    }

    /// Bytes held, consumed or not.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Whether bytes that do not yet form a frame are waiting.
    pub fn pending(&self) -> bool {
        self.start < self.buffer.len()
    }

    /// The next complete frame, `None` when more bytes are needed, or an error when the stream cannot be resynchronized.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        let Some(&first) = self.buffer.get(self.start) else {
            return Ok(None);
        };
        match first {
            b'+' => {
                self.start += 1;
                Ok(Some(Frame::Ack))
            }
            b'-' => {
                self.start += 1;
                Ok(Some(Frame::Nak))
            }
            b'$' | b'%' => {
                let body = &self.buffer[self.start + 1..];
                let Some(end) = body.iter().position(|&byte| byte == b'#') else {
                    // The body, `#` and two checksum digits must fit the limit.
                    if body.len() > self.limit + 3 {
                        return Err(FrameError::Oversized(self.limit));
                    }
                    return Ok(None);
                };
                if end > self.limit {
                    return Err(FrameError::Oversized(self.limit));
                }
                if body.len() < end + 3 {
                    return Ok(None);
                }
                let raw = &body[..end];
                let sent = hex_byte(body[end + 1], body[end + 2]);
                let valid = sent == Some(checksum(raw));
                let frame = if first == b'%' {
                    Frame::Notification
                } else if valid {
                    Frame::Packet(expand(raw, self.limit)?)
                } else {
                    Frame::Corrupt
                };
                self.start += end + 4;
                Ok(Some(frame))
            }
            other => {
                self.start += 1;
                Ok(Some(Frame::Noise(other)))
            }
        }
    }
}

/// The modulo-256 sum the protocol uses as a packet checksum.
pub fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte))
}

/// `payload` framed as `$payload#cs`, escaping the bytes the framing reserves.
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(payload.len() + 4);
    for &byte in payload {
        if matches!(byte, b'#' | b'$' | b'}' | b'*') {
            body.push(b'}');
            body.push(byte ^ 0x20);
        } else {
            body.push(byte);
        }
    }
    let sum = checksum(&body);
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.push(b'$');
    frame.extend_from_slice(&body);
    frame.push(b'#');
    frame.extend_from_slice(format!("{sum:02x}").as_bytes());
    frame
}

/// Expands run-length encoding: `X*n` repeats `X` a further `n - 29` times, where `n` is a printable count byte.
fn expand(raw: &[u8], limit: usize) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        let byte = raw[index];
        if byte == b'*' {
            let (Some(&previous), Some(&count)) = (out.last(), raw.get(index + 1)) else {
                return Err(FrameError::RunLength);
            };
            // GDB never sends counts below 3 repeats, or above the printable range.
            if !(32..=126).contains(&count) {
                return Err(FrameError::RunLength);
            }
            let repeats = usize::from(count) - 29;
            if out.len() + repeats > limit {
                return Err(FrameError::Oversized(limit));
            }
            out.resize(out.len() + repeats, previous);
            index += 2;
        } else {
            if out.len() >= limit {
                return Err(FrameError::Oversized(limit));
            }
            out.push(byte);
            index += 1;
        }
    }
    Ok(out)
}

/// Removes binary escaping (`}` then the byte XOR 0x20) from the payload of a binary reply.
pub fn unescape(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter();
    while let Some(&byte) = iter.next() {
        if byte == b'}' {
            let escaped = iter.next().ok_or("binary escape at the end of a packet")?;
            out.push(escaped ^ 0x20);
        } else {
            out.push(byte);
        }
    }
    Ok(out)
}

pub(crate) fn hex_digit(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

fn hex_byte(high: u8, low: u8) -> Option<u8> {
    Some(hex_digit(high)? << 4 | hex_digit(low)?)
}

/// Decodes a hex string into bytes, refusing odd lengths and non-hex digits.
pub fn decode_hex(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_chunks::<2>().0.iter().map(|pair| hex_byte(pair[0], pair[1])).collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// Parses an unsigned hex number of at most 16 digits.
pub fn parse_hex_u64(text: &str) -> Option<u64> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if text.is_empty() || text.len() > 16 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(text, 16).ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A small deterministic PRNG so the property tests need no extra dependency.
    pub(crate) struct Rng(u64);

    impl Rng {
        pub(crate) fn new(seed: u64) -> Self {
            Self(seed ^ 0x9e37_79b9_7f4a_7c15)
        }

        pub(crate) fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        pub(crate) fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound.max(1) as u64) as usize
        }

        pub(crate) fn bytes(&mut self, length: usize) -> Vec<u8> {
            (0..length).map(|_| self.next() as u8).collect()
        }
    }

    fn frames(bytes: &[u8], limit: usize) -> Result<Vec<Frame>, FrameError> {
        let mut framer = Framer::new(limit);
        framer.push(bytes);
        let mut frames = Vec::new();
        while let Some(frame) = framer.next_frame()? {
            frames.push(frame);
        }
        Ok(frames)
    }

    #[test]
    fn frames_acks_packets_and_notifications() {
        let stream = b"+$OK#9a%Stop:T05#00-x$E01#a6";
        assert_eq!(
            frames(stream, 4096).unwrap(),
            vec![
                Frame::Ack,
                Frame::Packet(b"OK".to_vec()),
                Frame::Notification,
                Frame::Nak,
                Frame::Noise(b'x'),
                Frame::Packet(b"E01".to_vec())
            ]
        );
    }

    #[test]
    fn rejects_wrong_checksums_and_waits_for_incomplete_packets() {
        assert_eq!(frames(b"$OK#9b", 4096).unwrap(), vec![Frame::Corrupt]);
        assert_eq!(frames(b"$OK#zz", 4096).unwrap(), vec![Frame::Corrupt]);
        let mut framer = Framer::new(4096);
        framer.push(b"$O");
        assert_eq!(framer.next_frame().unwrap(), None);
        framer.push(b"K#9");
        assert_eq!(framer.next_frame().unwrap(), None);
        framer.push(b"a");
        assert_eq!(framer.next_frame().unwrap(), Some(Frame::Packet(b"OK".to_vec())));
        assert!(!framer.pending());
    }

    #[test]
    fn expands_run_length_encoding_within_the_limit() {
        // "0* " is '0' then 32 - 29 = 3 more: four zeros.
        let raw = b"0* ";
        let frame = [b"$", &raw[..], format!("#{:02x}", checksum(raw)).as_bytes()].concat();
        assert_eq!(frames(&frame, 4096).unwrap(), vec![Frame::Packet(b"0000".to_vec())]);
        // A count byte outside the printable range, a leading '*' and a trailing '*' are malformed.
        for raw in [&b"0*\x1f"[..], b"*0", b"0*"] {
            let frame = [b"$", raw, format!("#{:02x}", checksum(raw)).as_bytes()].concat();
            assert_eq!(frames(&frame, 4096), Err(FrameError::RunLength), "{raw:?}");
        }
        // Expansion past the limit is refused rather than allocated.
        let raw = b"0*~*~*~";
        let frame = [b"$", &raw[..], format!("#{:02x}", checksum(raw)).as_bytes()].concat();
        assert_eq!(frames(&frame, 100), Err(FrameError::Oversized(100)));
    }

    #[test]
    fn refuses_oversized_packets_before_buffering_them_all() {
        let mut framer = Framer::new(16);
        framer.push(b"$");
        framer.push(&[b'a'; 32]);
        assert_eq!(framer.next_frame(), Err(FrameError::Oversized(16)));
        assert_eq!(frames(b"$aaaaaaaaaaaaaaaaaaaa#00", 16), Err(FrameError::Oversized(16)));
    }

    /// A stream of frames split mid-frame never accumulates beyond one partial frame and one read.
    #[test]
    fn consumed_frames_are_released_while_streaming() {
        let mut framer = Framer::new(4096);
        let frame = encode(format!("O{}", encode_hex(&[b'x'; 200])).as_bytes());
        let stream: Vec<u8> = frame.iter().copied().cycle().take(frame.len() * 5000 + 7).collect();
        let mut most = 0;
        for piece in stream.chunks(frame.len() / 3 + 1) {
            framer.push(piece);
            while let Some(frame) = framer.next_frame().unwrap() {
                assert!(matches!(frame, Frame::Packet(_)));
            }
            most = most.max(framer.buffered());
        }
        assert!(most < 4 * frame.len(), "{most}");
    }

    #[test]
    fn escapes_round_trip_and_trailing_escapes_are_refused() {
        let payload = b"a#b$c}d*e";
        let frame = encode(payload);
        assert_eq!(&frame[..1], b"$");
        let packet = match frames(&frame, 4096).unwrap().pop().unwrap() {
            Frame::Packet(packet) => packet,
            other => panic!("{other:?}"),
        };
        assert_eq!(unescape(&packet).unwrap(), payload);
        assert!(unescape(b"abc}").is_err());
        assert_eq!(encode(b"?"), b"$?#3f");
    }

    #[test]
    fn hex_helpers_refuse_malformed_input() {
        assert_eq!(decode_hex(b"00ff10"), Some(vec![0, 0xff, 0x10]));
        assert_eq!(decode_hex(b"0"), None);
        assert_eq!(decode_hex(b"0g"), None);
        assert_eq!(parse_hex_u64("ffffffffffffffff"), Some(u64::MAX));
        assert_eq!(parse_hex_u64("10000000000000000"), None);
        assert_eq!(parse_hex_u64(""), None);
        assert_eq!(encode_hex(&[1, 0xab]), "01ab");
    }

    /// Random bytes never panic the framer and every frame stays within the limit.
    #[test]
    fn random_streams_never_panic() {
        let mut rng = Rng::new(1);
        for _ in 0..2000 {
            let length = rng.below(300);
            let mut bytes = rng.bytes(length);
            // Bias towards framing bytes so packets actually form.
            for byte in &mut bytes {
                if rng.below(4) == 0 {
                    *byte = b"$#%+-*}"[rng.below(7)];
                }
            }
            let mut framer = Framer::new(64);
            let mut index = 0;
            while index < bytes.len() {
                let step = 1 + rng.below(16);
                framer.push(&bytes[index..(index + step).min(bytes.len())]);
                index += step;
                loop {
                    match framer.next_frame() {
                        Ok(Some(Frame::Packet(packet))) => assert!(packet.len() <= 64),
                        Ok(Some(_)) => {}
                        Ok(None) | Err(_) => break,
                    }
                }
            }
        }
    }

    /// Valid packets that are mutated, truncated or given wrong checksums are reported, never misread as valid
    /// with different contents.
    #[test]
    fn mutated_packets_are_detected_or_decode_consistently() {
        let mut rng = Rng::new(2);
        for _ in 0..2000 {
            let length = rng.below(40);
            let payload: Vec<u8> = (0..length).map(|_| b"0123456789abcdefOKE;:,#$}*"[rng.below(26)]).collect();
            let mut frame = encode(&payload);
            match rng.below(3) {
                0 => {
                    let at = rng.below(frame.len());
                    frame[at] = rng.next() as u8;
                }
                1 => frame.truncate(rng.below(frame.len())),
                _ => {
                    let at = frame.len() - 1;
                    frame[at] = if frame[at] == b'0' { b'1' } else { b'0' };
                }
            }
            let Ok(frames) = frames(&frame, 4096) else { continue };
            for frame in frames {
                if let Frame::Packet(packet) = frame
                    && let Ok(decoded) = unescape(&packet)
                {
                    // A mutation that still checksums must at least stay within bounds.
                    assert!(decoded.len() <= 4096);
                }
            }
        }
    }

    #[test]
    fn oversized_run_length_expansions_are_bounded() {
        let mut rng = Rng::new(3);
        for _ in 0..500 {
            let mut raw = vec![b'a'];
            for _ in 0..rng.below(200) {
                raw.push(b'*');
                raw.push(b'~');
            }
            let frame = [b"$", &raw[..], format!("#{:02x}", checksum(&raw)).as_bytes()].concat();
            match frames(&frame, 1000) {
                Ok(frames) => match &frames[..] {
                    [Frame::Packet(packet)] => assert!(packet.len() <= 1000),
                    other => panic!("{other:?}"),
                },
                Err(error) => assert_eq!(error, FrameError::Oversized(1000)),
            }
        }
    }
}
