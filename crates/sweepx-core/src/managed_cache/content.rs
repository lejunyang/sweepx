//! Compact CAS ownership keys keep large indexes bounded without retaining hex strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ContentKey {
    hash: [u8; 64],
    length: u8,
    executable: bool,
}
impl ContentKey {
    pub fn parse(key: &str) -> Result<Self, String> {
        let (prefix, name) = key.split_once('/').ok_or("invalid_content_key")?;
        let (name, executable) = name
            .strip_suffix("-exec")
            .map_or((name, false), |n| (n, true));
        let hex = format!("{prefix}{name}");
        if prefix.len() != 2 || !matches!(hex.len(), 64 | 128) {
            return Err("invalid_content_key".into());
        }
        let mut hash = [0; 64];
        for (i, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let digit = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                _ => None,
            };
            hash[i] = digit(pair[0])
                .zip(digit(pair[1]))
                .map(|(a, b)| a * 16 + b)
                .ok_or("invalid_content_key")?;
        }
        Ok(Self {
            hash,
            length: (hex.len() / 2) as u8,
            executable,
        })
    }
    pub fn path(self) -> String {
        let hex: String = self.hash[..self.length as usize]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!(
            "{}/{}{}",
            &hex[..2],
            &hex[2..],
            if self.executable { "-exec" } else { "" }
        )
    }
}
