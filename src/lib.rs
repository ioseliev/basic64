

const ALPHABET: &'static [u8] = b"\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
abcdefghijklmnopqrstuvwxyz\
0123456789+/\
";

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
        0 => { },
        1 => {
            unsafe {
                let a = *input.get_unchecked(trailing_idx) as usize;
                buffer.push(ALPHABET[a >> 2] as char);
                buffer.push(ALPHABET[(a & 0x03) << 4] as char);
                buffer.push_str("==");
            }
        },
        2 => {
            unsafe {
                let a = *input.get_unchecked(trailing_idx) as usize;
                let b = *input.get_unchecked(trailing_idx + 1) as usize;
                buffer.push(ALPHABET[a >> 2] as char);
                buffer.push(ALPHABET[((a & 0x3) << 4) | (b >> 4)] as char);
                buffer.push(ALPHABET[(b & 0x0F) << 2] as char);
                buffer.push('=');
            }
        },
        _ => unreachable!(),
    }
}

/// Decodes a base64-encoded string from `input` into `output`, returning the number of decoded bytes.
/// 
/// # Panics
///
/// This function panics if
/// - `output` is of insufficient length to fit the decoded data in its full.
/// - A character outside of the base64 alphabet (`[A-Za-z0-9+/]`) is found in `input`.
pub fn decode_into<I: AsRef<[u8]>>(input: I, output: &mut [u8]) -> usize {
    #[inline]
    fn decode_fn(value: u8) -> u8 {
        match value {
            v @ b'A'..=b'Z' => v - b'A',
            v @ b'a'..=b'z' => v - b'a' + 26,
            v @ b'0'..=b'9' => v - b'0' + 52,
            b'/' => 62,
            b'+' => 63,
            b'=' => 64,
            _ => unreachable!(),
        }
    }
    
    let input = input.as_ref();
    assert!(output.len() >= needed_len!(decoding input.len()), "`basic64::decode_into` called on `output` with insufficient len.");

    for (i, j) in (0..input.len().saturating_sub(3)).step_by(4)
                          .zip((0..output.len().saturating_sub(2)).step_by(3)) {
        unsafe {
            let a = decode_fn(*input.get_unchecked(i));
            let b = decode_fn(*input.get_unchecked(i + 1));
            let c = decode_fn(*input.get_unchecked(i + 2));
            let d = decode_fn(*input.get_unchecked(i + 3));
            *output.get_unchecked_mut(j) = a << 2 | b >> 4;
            if c != 64 {
                *output.get_unchecked_mut(j + 1) = (b & 0x0F) << 4 | c >> 2;
                if d != 64 {
                    *output.get_unchecked_mut(j + 2) = (c & 0x03) << 6 | d;
                } else {
                    return j + 2;
                }
            } else {
                return j + 1;
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
            "",
            "Zg==",
            "Zm8=",
            "Zm9v",
            "Zm9vYg==",
            "Zm9vYmE=",
            "Zm9vYmFy",
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
            "",
            "Zg==",
            "Zm8=",
            "Zm9v",
            "Zm9vYg==",
            "Zm9vYmE=",
            "Zm9vYmFy",
        ];
        let expected = ["", "f", "fo", "foo", "foob", "fooba", "foobar"];

        let mut output = [0u8; 6];
        for i in 0..inputs.len() {
            let n = decode_into(inputs[i], &mut output);
            assert_eq!(&output[..n], expected[i].as_bytes());
        }
    }
}
