const ALPHABET: &'static [u8] = b"\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
abcdefghijklmnopqrstuvwxyz\
0123456789+/\
";
const REV_ALPHABET: [u8; 256] = const {
    let mut ret = [64u8; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        ret[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    ret
};

/// Rounds up `len` to be an exact (en/de)coding buffer length.ii
///
/// # Examples
///
/// ```
/// let mut input = [0u8; basic64::round_len!(enc 8_192)];
/// ```
#[macro_export]
macro_rules! round_len {
    (enc $len:expr) => {
        ($len + 2) / 3 * 3
    };
    (enc $len:expr) => {
        ($len + 3) & !3
    };
}

macro_rules! needed_len {
    (encoding $input:expr) => {
        ($input + 2) / 3 * 4
    };
    (decoding $input:expr) => {
        ($input + 3) / 4 * 3
    };
}

/// Encode `input` to base64, returning a newly allocated `String`.
pub fn encode(input: &[u8]) -> String {
    let mut output = String::with_capacity(needed_len!(encoding input.len()));
    encode_into(input, &mut output);
    output
}

/// Encode `input` to base64, appending the result to `buffer`.
pub fn encode_into(input: &[u8], buffer: &mut String) {
    buffer.reserve(needed_len!(encoding input.len()));
    let mut trailing_idx = 0usize;

    for i in (0..input.len().saturating_sub(2)).step_by(3) {
        // SAFETY All accesses are guaranteed to be in-bound.
        // The use of unsafe is due merely for performance.
        unsafe {
            let a = *input.get_unchecked(i) as usize;
            let b = *input.get_unchecked(i + 1) as usize;
            let c = *input.get_unchecked(i + 2) as usize;
            buffer.push(ALPHABET[a >> 2] as char);
            buffer.push(ALPHABET[((a << 4) & 0x30) | (b >> 4)] as char);
            buffer.push(ALPHABET[((b << 2) & 0x3C) | (c >> 6)] as char);
            buffer.push(ALPHABET[c & 0x3F] as char);
        }
        trailing_idx = i + 3;
    }

    match input.len() - trailing_idx {
        0 => {}
        1 => unsafe {
            let a = *input.get_unchecked(trailing_idx) as usize;
            buffer.push(ALPHABET[a >> 2] as char);
            buffer.push(ALPHABET[(a & 0x03) << 4] as char);
            buffer.push_str("==");
        },
        2 => unsafe {
            let a = *input.get_unchecked(trailing_idx) as usize;
            let b = *input.get_unchecked(trailing_idx + 1) as usize;
            buffer.push(ALPHABET[a >> 2] as char);
            buffer.push(ALPHABET[((a & 0x3) << 4) | (b >> 4)] as char);
            buffer.push(ALPHABET[(b & 0x0F) << 2] as char);
            buffer.push('=');
        },
        _ => unreachable!(),
    }
}

/// Decodes as much from `input` as possible; returns a newly allocated `Vec<u8>`.
pub fn decode<I: AsRef<[u8]>>(input: I) -> Vec<u8> {
    let input = input.as_ref();
    let mut ret = Vec::with_capacity(needed_len!(decoding input.len()));
    let _ = decode_into(input, &mut ret);
    ret
}

/// Decodes a base64-encoded string from `input` appending the result to `output` while there are valid characters;
/// returns the number of decoded bytes.
pub fn decode_into<I: AsRef<[u8]>>(input: I, output: &mut Vec<u8>) -> usize {
    let input = input.as_ref();

    if input.len() < 4 {
        return 0;
    }

    let needed_len = needed_len!(decoding input.len());
    output.reserve(needed_len);

    for (i, j) in (0..input.len().saturating_sub(3))
        .step_by(4)
        .zip((0..needed_len.saturating_sub(2)).step_by(3))
    {
        unsafe {
            let a = REV_ALPHABET[*input.get_unchecked(i) as usize];
            let b = REV_ALPHABET[*input.get_unchecked(i + 1) as usize];
            let c = REV_ALPHABET[*input.get_unchecked(i + 2) as usize];
            let d = REV_ALPHABET[*input.get_unchecked(i + 3) as usize];
            if a != 64 && b != 64 {
                output.push(a << 2 | b >> 4);
                if c != 64 {
                    output.push((b & 0x0F) << 4 | c >> 2);
                    if d != 64 {
                        output.push((c & 0x03) << 6 | d);
                    } else {
                        return j + 2;
                    }
                } else {
                    return j + 1;
                }
            } else {
                return j;
            }
        }
    }

    needed_len!(decoding input.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode() {
        let inputs = ["", "f", "fo", "foo", "foob", "fooba", "foobar"];
        let expected = [
            "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy",
        ];

        let mut output = String::with_capacity(expected.last().unwrap().len());
        for i in 0..inputs.len() {
            encode_into(inputs[i].as_bytes(), &mut output);
            assert_eq!(output, expected[i]);
            output.clear();
        }
    }

    #[test]
    fn decode() {
        let inputs = [
            "", " ", "  ", "   ", "    ", "Zg==", "Zg  ", "Zm8=", "Zm8 ", "Zm9v", "Zm9vYg==",
            "Zm9vYmE=", "Zm9vYmFy",
        ];
        let expected = [
            "", "", "", "", "", "f", "f", "fo", "fo", "foo", "foob", "fooba", "foobar",
        ];

        let mut output = Vec::with_capacity(8);
        for i in 0..inputs.len() {
            let n = decode_into(inputs[i], &mut output);
            assert_eq!(&output[..n], expected[i].as_bytes());
            output.clear();
        }
    }
}
