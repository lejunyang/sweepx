//! Terminal input with bounded framing before key decoding.
//!
//! A complete, unrecognized CSI reply must be consumed as one frame. Keeping it as an
//! incomplete key can swallow every later key (crossterm issue #1104). Framing lives here;
//! the existing protocols and key types are decoded by terminput's crossterm adapter.

use crate::BrowserEventSource;
use crossterm::event::Event;
use std::{io, time::Duration};

/// Input source shared by the scan, cleanup and file-detail views.
///
/// Unix reads one bounded chunk at a time on the foreground UI thread. No background reader
/// competes for stdin; Windows retains crossterm's native console input implementation.
#[derive(Default)]
pub struct TerminalEventSource {
    #[cfg(unix)]
    input: unix::Input,
}

impl BrowserEventSource for TerminalEventSource {
    fn poll_event(&mut self, timeout: Duration) -> io::Result<Option<Event>> {
        #[cfg(unix)]
        {
            self.input.poll(timeout)
        }
        #[cfg(not(unix))]
        crate::CrosstermEventSource.poll_event(timeout)
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::time::Instant;

    const CHUNK: usize = 1024;
    const ESCAPE_WAIT: Duration = Duration::from_millis(30);
    const FRAME_WAIT: Duration = Duration::from_millis(250);
    const STRING_WAIT: Duration = Duration::from_secs(1);

    pub(super) struct Input {
        decoder: Decoder,
        bytes: [u8; CHUNK],
        offset: usize,
        length: usize,
    }

    impl Default for Input {
        fn default() -> Self {
            Self {
                decoder: Decoder::default(),
                bytes: [0; CHUNK],
                offset: 0,
                length: 0,
            }
        }
    }

    impl Input {
        pub(super) fn poll(&mut self, timeout: Duration) -> io::Result<Option<Event>> {
            self.poll_fd(libc::STDIN_FILENO, timeout)
        }

        fn poll_fd(
            &mut self,
            input: std::os::fd::RawFd,
            timeout: Duration,
        ) -> io::Result<Option<Event>> {
            if let Some(event) = self.decoder.expire(Instant::now())? {
                return Ok(Some(event));
            }
            if let Some(event) = self.drain() {
                return Ok(Some(event));
            }
            let wait = self
                .decoder
                .wait(Instant::now())
                .map_or(timeout, |w| w.min(timeout));
            let mut fd = libc::pollfd {
                fd: input,
                events: libc::POLLIN,
                revents: 0,
            };
            // Round up a partial millisecond; zero still performs one readiness check.
            let millis = wait.as_nanos().div_ceil(1_000_000);
            // SAFETY: fd names one initialized pollfd for the duration of this bounded call.
            let ready = unsafe { libc::poll(&mut fd, 1, millis.min(i32::MAX as u128) as i32) };
            if ready < 0 {
                return Err(io::Error::last_os_error());
            }
            if ready == 0 {
                return self.decoder.expire(Instant::now());
            }
            if fd.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "terminal input closed",
                ));
            }
            // Raw mode uses VMIN=1. This is the sole stdin reader and reads only once after
            // readiness, never a blocking drain-until-empty loop or a shared fd flag change.
            // SAFETY: bytes is writable for exactly the passed length; stdin remains process-owned.
            let count = unsafe { libc::read(input, self.bytes.as_mut_ptr().cast(), CHUNK) };
            if count < 0 {
                let error = io::Error::last_os_error();
                return if error.kind() == io::ErrorKind::WouldBlock {
                    Ok(None)
                } else {
                    Err(error)
                };
            }
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "terminal input closed",
                ));
            }
            self.offset = 0;
            self.length = count as usize;
            Ok(self.drain())
        }

        fn drain(&mut self) -> Option<Event> {
            while self.offset < self.length {
                let byte = self.bytes[self.offset];
                self.offset += 1;
                if let Some(event) = self.decoder.advance(byte, Instant::now()) {
                    return Some(event);
                }
            }
            None
        }
    }

    #[derive(Default, Clone, Copy)]
    enum Mode {
        #[default]
        Key,
        Csi,
        Ss3,
        DiscardCsi,
        String {
            escaped: bool,
        },
        Paste {
            matched: usize,
        },
        Mouse {
            remaining: u8,
        },
    }

    #[derive(Default)]
    struct Decoder {
        frame: Vec<u8>,
        mode: Mode,
        updated: Option<Instant>,
    }

    impl Decoder {
        fn reset(&mut self) {
            self.frame.clear();
            self.mode = Mode::Key;
            self.updated = None;
        }

        fn wait(&self, now: Instant) -> Option<Duration> {
            let limit = match self.mode {
                Mode::Key if self.frame == b"\x1b" => ESCAPE_WAIT,
                Mode::String { .. } | Mode::Paste { .. } => STRING_WAIT,
                _ => FRAME_WAIT,
            };
            self.updated
                .map(|updated| limit.saturating_sub(now.duration_since(updated)))
        }

        fn expire(&mut self, now: Instant) -> io::Result<Option<Event>> {
            if self.wait(now) != Some(Duration::ZERO) {
                return Ok(None);
            }
            let escape = self.frame == b"\x1b";
            let string = matches!(self.mode, Mode::String { .. } | Mode::Paste { .. });
            self.reset();
            if string {
                // Resuming key interpretation could turn a delayed paste/control-string tail
                // into a cleanup action. End the view with terminal restoration instead.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "terminal control string did not finish",
                ));
            }
            Ok(escape.then(|| Event::Key(crossterm::event::KeyCode::Esc.into())))
        }

        fn decode(&mut self) -> Option<Event> {
            // A numbered cursor-position reply is not an F3 key. The UI never requests
            // modified function keys, and must not reinterpret terminal metadata as actions.
            if self.frame.starts_with(b"\x1b[")
                && self.frame.get(2).is_some_and(u8::is_ascii_digit)
                && self.frame.last() == Some(&b'R')
            {
                self.reset();
                return None;
            }
            let event = terminput::Event::parse_from(&self.frame)
                .ok()
                .flatten()
                .and_then(|event| terminput_crossterm::to_crossterm(event).ok());
            // None means this *complete* frame is unsupported, never that subsequent input
            // belongs to it. This also bounds retained state independently of the decoder.
            self.reset();
            event
        }

        fn advance(&mut self, byte: u8, now: Instant) -> Option<Event> {
            self.updated = Some(now);
            match self.mode {
                Mode::String { escaped } => {
                    if byte == 7 || (escaped && byte == b'\\') {
                        self.reset();
                    } else {
                        self.mode = Mode::String {
                            escaped: byte == 27,
                        };
                    }
                    return None;
                }
                Mode::Paste { matched } => {
                    // Paste content is never replayed as actions (including Trash confirmation).
                    let end = b"\x1b[201~";
                    let matched = if byte == end[matched] {
                        matched + 1
                    } else {
                        usize::from(byte == 27)
                    };
                    if matched == end.len() {
                        self.reset();
                    } else {
                        self.mode = Mode::Paste { matched };
                    }
                    return None;
                }
                Mode::Mouse { remaining } => {
                    if remaining == 1 {
                        self.reset();
                    } else {
                        self.mode = Mode::Mouse {
                            remaining: remaining - 1,
                        };
                    }
                    return None;
                }
                Mode::DiscardCsi => {
                    if (0x40..=0x7e).contains(&byte) {
                        self.reset();
                    }
                    return None;
                }
                _ => {}
            }
            if self.frame.len() == CHUNK {
                self.frame.clear();
                self.mode = Mode::DiscardCsi;
                if (0x40..=0x7e).contains(&byte) {
                    self.reset();
                }
                return None;
            }
            self.frame.push(byte);
            if self.frame.len() == 1 && byte == 27 {
                return None;
            }
            if self.frame.len() == 2 && self.frame[0] == 27 {
                match byte {
                    b'[' => {
                        self.mode = Mode::Csi;
                        return None;
                    }
                    b'O' => {
                        self.mode = Mode::Ss3;
                        return None;
                    }
                    b']' | b'P' | b'X' | b'^' | b'_' => {
                        self.frame.clear();
                        self.mode = Mode::String { escaped: false };
                        return None;
                    }
                    _ => {}
                }
            }
            if matches!(self.mode, Mode::Csi | Mode::Ss3) {
                if !(0x40..=0x7e).contains(&byte) || self.frame == b"\x1b[[" {
                    return None;
                }
                if self.frame == b"\x1b[200~" {
                    self.frame.clear();
                    self.mode = Mode::Paste { matched: 0 };
                    return None;
                }
                if self.frame == b"\x1b[M" {
                    self.frame.clear();
                    self.mode = Mode::Mouse { remaining: 3 };
                    return None;
                }
                return self.decode();
            }
            let text = if self.frame[0] == 27 {
                &self.frame[1..]
            } else {
                &self.frame[..]
            };
            if let Err(error) = std::str::from_utf8(text)
                && error.error_len().is_none()
                && text.len() < 4
            {
                return None;
            }
            self.decode()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
        use std::{
            io::Write,
            os::{fd::AsRawFd, unix::net::UnixStream},
        };

        fn feed(decoder: &mut Decoder, bytes: &[u8], now: Instant) -> Vec<Event> {
            bytes
                .iter()
                .filter_map(|byte| decoder.advance(*byte, now))
                .collect()
        }

        fn key(code: KeyCode) -> Event {
            Event::Key(code.into())
        }

        #[test]
        fn terminal_replies_never_swallow_later_actions() {
            // DECRPM, theme notification, DA, cursor position and OSC/DCS replies are
            // terminal metadata, not keyboard input. Include a reply split at every byte.
            for reply in [
                &b"\x1b[?2026;2$y"[..],
                &b"\x1b[?997;1n"[..],
                &b"\x1b[?1;2c"[..],
                &b"\x1b[12;30R"[..],
                &b"\x1b]11;rgb:ffff/0000/0000\x07"[..],
                &b"\x1bP>|terminal d q\r\x1b\\"[..],
            ] {
                let mut decoder = Decoder::default();
                let now = Instant::now();
                let mut events = Vec::new();
                for (index, byte) in reply.iter().enumerate() {
                    let at = now + Duration::from_millis(index as u64);
                    events.extend(feed(&mut decoder, &[*byte], at));
                    assert!(decoder.expire(at).unwrap().is_none());
                }
                events.extend(feed(
                    &mut decoder,
                    b"\x1b[B\r q",
                    now + Duration::from_millis(100),
                ));
                assert_eq!(
                    events,
                    [
                        key(KeyCode::Down),
                        key(KeyCode::Enter),
                        key(KeyCode::Char(' ')),
                        key(KeyCode::Char('q'))
                    ],
                    "reply={reply:?}"
                );
            }
        }

        #[test]
        fn legacy_ss3_and_enhanced_keyboard_encodings_agree() {
            for input in [
                &b"\x1b[A\x1b[B\r q"[..],
                &b"\x1bOA\x1bOB\r q"[..],
                &b"\x1b[1;1A\x1b[1;1B\x1b[13u\x1b[32u\x1b[113u"[..],
            ] {
                assert_eq!(
                    feed(&mut Decoder::default(), input, Instant::now()),
                    [
                        key(KeyCode::Up),
                        key(KeyCode::Down),
                        key(KeyCode::Enter),
                        key(KeyCode::Char(' ')),
                        key(KeyCode::Char('q')),
                    ]
                );
            }
        }

        #[test]
        fn modifiers_repeats_releases_and_utf8_are_preserved() {
            assert_eq!(
                feed(
                    &mut Decoder::default(),
                    b"\x03\x1b[113;1:2u\x1b[113;1:3u\xe4\xb8\xad\x1bx",
                    Instant::now()
                ),
                [
                    Event::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
                    Event::Key(KeyEvent::new_with_kind(
                        KeyCode::Char('q'),
                        KeyModifiers::NONE,
                        KeyEventKind::Repeat
                    )),
                    Event::Key(KeyEvent::new_with_kind(
                        KeyCode::Char('q'),
                        KeyModifiers::NONE,
                        KeyEventKind::Release
                    )),
                    key(KeyCode::Char('中')),
                    Event::Key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT)),
                ]
            );
        }

        #[test]
        fn paste_and_control_string_contents_cannot_become_actions() {
            let now = Instant::now();
            let mut decoder = Decoder::default();
            assert!(feed(&mut decoder, b"\x1b[200~d\rq q\x1b[B", now).is_empty());
            assert_eq!(
                feed(&mut decoder, b"\x1b[201~q", now),
                [key(KeyCode::Char('q'))]
            );
            assert!(feed(&mut decoder, b"\x1b]anything d\rq", now).is_empty());
            assert_eq!(
                feed(&mut decoder, b"\x1b\\q", now),
                [key(KeyCode::Char('q'))]
            );
        }

        #[test]
        fn incomplete_and_oversized_frames_have_bounded_recovery() {
            let now = Instant::now();
            let mut decoder = Decoder::default();
            assert!(feed(&mut decoder, b"\x1b", now).is_empty());
            assert!(
                decoder
                    .expire(now + Duration::from_millis(10))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                decoder.expire(now + Duration::from_millis(100)).unwrap(),
                Some(key(KeyCode::Esc))
            );
            assert!(feed(&mut decoder, b"\x1b[?", now).is_empty());
            assert!(
                decoder
                    .expire(now + Duration::from_secs(2))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(feed(&mut decoder, b"q", now), [key(KeyCode::Char('q'))]);
            assert!(feed(&mut decoder, b"\x1b[?", now).is_empty());
            for _ in 0..10_000 {
                assert!(decoder.advance(b'0', now).is_none());
            }
            assert!(decoder.frame.len() <= 1024);
            assert_eq!(feed(&mut decoder, b"yq", now), [key(KeyCode::Char('q'))]);
            assert!(feed(&mut decoder, b"\x1b]unterminated", now).is_empty());
            assert_eq!(
                decoder
                    .expire(now + Duration::from_secs(2))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }

        #[test]
        fn zero_timeout_reads_ready_input_and_keeps_remaining_keys() {
            let (reader, mut writer) = UnixStream::pair().unwrap();
            let mut input = Input::default();
            assert_eq!(
                input.poll_fd(reader.as_raw_fd(), Duration::ZERO).unwrap(),
                None
            );
            writer.write_all(b"\x1b[?2026;2$y\x1b[B\r q").unwrap();
            for expected in [
                key(KeyCode::Down),
                key(KeyCode::Enter),
                key(KeyCode::Char(' ')),
                key(KeyCode::Char('q')),
            ] {
                assert_eq!(
                    input.poll_fd(reader.as_raw_fd(), Duration::ZERO).unwrap(),
                    Some(expected)
                );
            }
            assert_eq!(
                input.poll_fd(reader.as_raw_fd(), Duration::ZERO).unwrap(),
                None
            );
            drop(writer);
            assert_eq!(
                input
                    .poll_fd(reader.as_raw_fd(), Duration::ZERO)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }

        #[test]
        fn fragmented_replies_return_control_without_waiting_for_a_key() {
            let (reader, mut writer) = UnixStream::pair().unwrap();
            let mut input = Input::default();
            writer.write_all(b"\x1b[?").unwrap();
            assert_eq!(
                input.poll_fd(reader.as_raw_fd(), Duration::ZERO).unwrap(),
                None
            );
            writer.write_all(b"2026;2$yq").unwrap();
            assert_eq!(
                input.poll_fd(reader.as_raw_fd(), Duration::ZERO).unwrap(),
                Some(key(KeyCode::Char('q')))
            );
        }
    }
}
