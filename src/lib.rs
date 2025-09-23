

const ALPHABET: &'static [u8] = b"\
ABCDEFGHIJKLMNOPQRSTUVWXYZ\
abcdefghijklmnopqrstuvwxyz\
0123456789+/\
";

pub fn encode(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len() / 3 * 4);
    encode_into(input, &mut output);
    output
}

pub fn encode_into(input: &[u8], buffer: &mut String) {
    buffer.reserve(input.len() / 3 * 4);
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

#[cfg(test)]
mod tests {
    use super::*;
    
    
    #[test]
    fn test() {
        let inputs = ["", "foo", "foob", "fooba", "foobar"];
        let outputs = [
            "",
            "Zm9v",
            "Zm9vYg==",
            "Zm9vYmE=",
            "Zm9vYmFy",
        ];

        let mut output = String::with_capacity(outputs.last().unwrap().len());
        for i in 0..inputs.len() {
            encode_into(inputs[i].as_bytes(), &mut output);
            assert_eq!(output, outputs[i]);
            output.clear();
        }
    }
}
