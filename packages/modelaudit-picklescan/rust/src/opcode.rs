#[derive(Clone)]
pub(crate) enum ArgValue {
    None,
    Int(i64),
    UInt(usize),
    Text(String),
    Bytes(Vec<u8>),
}

impl ArgValue {
    pub(crate) fn as_i64(&self) -> Option<i64> {
        match self {
            ArgValue::Int(value) => Some(*value),
            ArgValue::UInt(value) => i64::try_from(*value).ok(),
            ArgValue::Text(value) => value.parse::<i64>().ok(),
            _ => None,
        }
    }

    pub(crate) fn global_parts(&self) -> (String, String) {
        match self {
            ArgValue::Text(value) => {
                let mut parts = value.splitn(2, ' ');
                let module = parts.next().unwrap_or_default().to_string();
                let name = parts.next().unwrap_or_default().to_string();
                (module, name)
            }
            _ => ("".to_string(), "".to_string()),
        }
    }

    pub(crate) fn coerce_text(&self) -> String {
        match self {
            ArgValue::Text(value) => value.clone(),
            ArgValue::Bytes(value) => String::from_utf8_lossy(value).to_string(),
            ArgValue::Int(value) => value.to_string(),
            ArgValue::UInt(value) => value.to_string(),
            ArgValue::None => "".to_string(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ParsedOpcode {
    pub(crate) name: &'static str,
    pub(crate) arg: ArgValue,
    pub(crate) pos: usize,
    pub(crate) next: usize,
}

#[derive(Debug)]
pub(crate) struct ParseError {
    pub(crate) message: String,
    pub(crate) exception_type: &'static str,
    pub(crate) report_index: Option<usize>,
}

impl ParseError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exception_type: "ValueError",
            report_index: None,
        }
    }

    pub(crate) fn at(mut self, index: usize) -> Self {
        self.report_index = Some(index);
        self
    }

    fn not_enough_fixed_width(read_kind: &'static str, index: usize) -> Self {
        Self {
            message: format!("not enough data in stream to read {read_kind}"),
            exception_type: "ValueError",
            report_index: Some(index),
        }
    }
}
pub(crate) fn parse_opcode(
    payload: &[u8],
    index: usize,
    limit: usize,
) -> Result<ParsedOpcode, ParseError> {
    if index >= limit {
        return Err(ParseError::new("unexpected end of pickle stream"));
    }
    let op = payload[index];
    let mut cursor = index + 1;

    let parsed = match op {
        b'I' => ParsedOpcode {
            name: "INT",
            arg: ArgValue::Text(read_line_text(payload, &mut cursor, limit)?),
            pos: index,
            next: cursor,
        },
        b'J' => ParsedOpcode {
            name: "BININT",
            arg: ArgValue::Int(read_i32_le(payload, &mut cursor, limit)? as i64),
            pos: index,
            next: cursor,
        },
        b'K' => ParsedOpcode {
            name: "BININT1",
            arg: ArgValue::Int(read_u8(payload, &mut cursor, limit)? as i64),
            pos: index,
            next: cursor,
        },
        b'M' => ParsedOpcode {
            name: "BININT2",
            arg: ArgValue::Int(read_u16_le(payload, &mut cursor, limit)? as i64),
            pos: index,
            next: cursor,
        },
        b'L' => ParsedOpcode {
            name: "LONG",
            arg: ArgValue::Text(read_line_text(payload, &mut cursor, limit)?),
            pos: index,
            next: cursor,
        },
        0x8a => {
            let len = read_u8(payload, &mut cursor, limit)? as usize;
            let value = read_fixed_width_bytes(payload, &mut cursor, limit, len, "long1")?;
            ParsedOpcode {
                name: "LONG1",
                arg: ArgValue::Bytes(value),
                pos: index,
                next: cursor,
            }
        }
        0x8b => {
            let len = read_u32_le(payload, &mut cursor, limit)? as usize;
            let value = read_fixed_width_bytes(payload, &mut cursor, limit, len, "long4")?;
            ParsedOpcode {
                name: "LONG4",
                arg: ArgValue::Bytes(value),
                pos: index,
                next: cursor,
            }
        }
        b'S' => ParsedOpcode {
            name: "STRING",
            arg: ArgValue::Text(parse_pickle_string_literal(&read_line_bytes(
                payload,
                &mut cursor,
                limit,
            )?)),
            pos: index,
            next: cursor,
        },
        b'T' => {
            let len = read_u32_le(payload, &mut cursor, limit)? as usize;
            ParsedOpcode {
                name: "BINSTRING",
                arg: ArgValue::Bytes(read_variable_bytes(
                    payload,
                    &mut cursor,
                    limit,
                    len,
                    "string4",
                )?),
                pos: index,
                next: cursor,
            }
        }
        b'U' => {
            let len = read_u8(payload, &mut cursor, limit)? as usize;
            ParsedOpcode {
                name: "SHORT_BINSTRING",
                arg: ArgValue::Bytes(read_variable_bytes(
                    payload,
                    &mut cursor,
                    limit,
                    len,
                    "string1",
                )?),
                pos: index,
                next: cursor,
            }
        }
        b'B' => {
            let len = read_u32_le(payload, &mut cursor, limit)? as usize;
            ParsedOpcode {
                name: "BINBYTES",
                arg: ArgValue::Bytes(read_variable_bytes(
                    payload,
                    &mut cursor,
                    limit,
                    len,
                    "bytes4",
                )?),
                pos: index,
                next: cursor,
            }
        }
        b'C' => {
            let len = read_u8(payload, &mut cursor, limit)? as usize;
            ParsedOpcode {
                name: "SHORT_BINBYTES",
                arg: ArgValue::Bytes(read_variable_bytes(
                    payload,
                    &mut cursor,
                    limit,
                    len,
                    "bytes1",
                )?),
                pos: index,
                next: cursor,
            }
        }
        0x8e => {
            let len = read_u64_len(payload, &mut cursor, limit, index, "bytes8")?;
            ParsedOpcode {
                name: "BINBYTES8",
                arg: ArgValue::Bytes(read_variable_bytes(
                    payload,
                    &mut cursor,
                    limit,
                    len,
                    "bytes8",
                )?),
                pos: index,
                next: cursor,
            }
        }
        0x96 => {
            let len = read_u64_len(payload, &mut cursor, limit, index, "bytearray8")?;
            ParsedOpcode {
                name: "BYTEARRAY8",
                arg: ArgValue::Bytes(read_variable_bytes(
                    payload,
                    &mut cursor,
                    limit,
                    len,
                    "bytearray8",
                )?),
                pos: index,
                next: cursor,
            }
        }
        0x97 => simple_opcode("NEXT_BUFFER", index, cursor),
        0x98 => simple_opcode("READONLY_BUFFER", index, cursor),
        b'N' => simple_opcode("NONE", index, cursor),
        0x88 => simple_opcode("NEWTRUE", index, cursor),
        0x89 => simple_opcode("NEWFALSE", index, cursor),
        b'V' => ParsedOpcode {
            name: "UNICODE",
            arg: ArgValue::Text(read_line_raw_unicode(payload, &mut cursor, limit)?),
            pos: index,
            next: cursor,
        },
        0x8c => {
            let len = read_u8(payload, &mut cursor, limit)? as usize;
            ParsedOpcode {
                name: "SHORT_BINUNICODE",
                arg: ArgValue::Text(
                    String::from_utf8_lossy(&read_variable_bytes(
                        payload,
                        &mut cursor,
                        limit,
                        len,
                        "unicodestring1",
                    )?)
                    .to_string(),
                ),
                pos: index,
                next: cursor,
            }
        }
        b'X' => {
            let len = read_u32_le(payload, &mut cursor, limit)? as usize;
            ParsedOpcode {
                name: "BINUNICODE",
                arg: ArgValue::Text(
                    String::from_utf8_lossy(&read_variable_bytes(
                        payload,
                        &mut cursor,
                        limit,
                        len,
                        "unicodestring4",
                    )?)
                    .to_string(),
                ),
                pos: index,
                next: cursor,
            }
        }
        0x8d => {
            let len = read_u64_len(payload, &mut cursor, limit, index, "unicodestring8")?;
            ParsedOpcode {
                name: "BINUNICODE8",
                arg: ArgValue::Text(
                    String::from_utf8_lossy(&read_variable_bytes(
                        payload,
                        &mut cursor,
                        limit,
                        len,
                        "unicodestring8",
                    )?)
                    .to_string(),
                ),
                pos: index,
                next: cursor,
            }
        }
        b'F' => ParsedOpcode {
            name: "FLOAT",
            arg: ArgValue::Text(read_line_text(payload, &mut cursor, limit)?),
            pos: index,
            next: cursor,
        },
        b'G' => ParsedOpcode {
            name: "BINFLOAT",
            arg: ArgValue::Bytes(read_fixed_width_bytes(
                payload,
                &mut cursor,
                limit,
                8,
                "float8",
            )?),
            pos: index,
            next: cursor,
        },
        b']' => simple_opcode("EMPTY_LIST", index, cursor),
        b'a' => simple_opcode("APPEND", index, cursor),
        b'e' => simple_opcode("APPENDS", index, cursor),
        b'l' => simple_opcode("LIST", index, cursor),
        b')' => simple_opcode("EMPTY_TUPLE", index, cursor),
        b't' => simple_opcode("TUPLE", index, cursor),
        0x85 => simple_opcode("TUPLE1", index, cursor),
        0x86 => simple_opcode("TUPLE2", index, cursor),
        0x87 => simple_opcode("TUPLE3", index, cursor),
        b'}' => simple_opcode("EMPTY_DICT", index, cursor),
        b'd' => simple_opcode("DICT", index, cursor),
        b's' => simple_opcode("SETITEM", index, cursor),
        b'u' => simple_opcode("SETITEMS", index, cursor),
        0x8f => simple_opcode("EMPTY_SET", index, cursor),
        0x90 => simple_opcode("ADDITEMS", index, cursor),
        0x91 => simple_opcode("FROZENSET", index, cursor),
        b'0' => simple_opcode("POP", index, cursor),
        b'2' => simple_opcode("DUP", index, cursor),
        b'(' => simple_opcode("MARK", index, cursor),
        b'1' => simple_opcode("POP_MARK", index, cursor),
        b'g' => ParsedOpcode {
            name: "GET",
            arg: ArgValue::Text(read_line_text(payload, &mut cursor, limit)?),
            pos: index,
            next: cursor,
        },
        b'h' => ParsedOpcode {
            name: "BINGET",
            arg: ArgValue::Int(read_u8(payload, &mut cursor, limit)? as i64),
            pos: index,
            next: cursor,
        },
        b'j' => ParsedOpcode {
            name: "LONG_BINGET",
            arg: ArgValue::Int(read_u32_le(payload, &mut cursor, limit)? as i64),
            pos: index,
            next: cursor,
        },
        b'p' => ParsedOpcode {
            name: "PUT",
            arg: ArgValue::Text(read_line_text(payload, &mut cursor, limit)?),
            pos: index,
            next: cursor,
        },
        b'q' => ParsedOpcode {
            name: "BINPUT",
            arg: ArgValue::Int(read_u8(payload, &mut cursor, limit)? as i64),
            pos: index,
            next: cursor,
        },
        b'r' => ParsedOpcode {
            name: "LONG_BINPUT",
            arg: ArgValue::Int(read_u32_le(payload, &mut cursor, limit)? as i64),
            pos: index,
            next: cursor,
        },
        0x94 => simple_opcode("MEMOIZE", index, cursor),
        0x82 => ParsedOpcode {
            name: "EXT1",
            arg: ArgValue::Int(read_u8(payload, &mut cursor, limit)? as i64),
            pos: index,
            next: cursor,
        },
        0x83 => ParsedOpcode {
            name: "EXT2",
            arg: ArgValue::Int(read_u16_le(payload, &mut cursor, limit)? as i64),
            pos: index,
            next: cursor,
        },
        0x84 => ParsedOpcode {
            name: "EXT4",
            arg: ArgValue::Int(read_u32_le(payload, &mut cursor, limit)? as i64),
            pos: index,
            next: cursor,
        },
        b'c' => {
            let module = read_line_text(payload, &mut cursor, limit)?;
            let name = read_line_text(payload, &mut cursor, limit)?;
            ParsedOpcode {
                name: "GLOBAL",
                arg: ArgValue::Text(format!("{} {}", module, name)),
                pos: index,
                next: cursor,
            }
        }
        0x93 => simple_opcode("STACK_GLOBAL", index, cursor),
        b'R' => simple_opcode("REDUCE", index, cursor),
        b'b' => simple_opcode("BUILD", index, cursor),
        b'i' => {
            let module = read_line_text(payload, &mut cursor, limit)?;
            let name = read_line_text(payload, &mut cursor, limit)?;
            ParsedOpcode {
                name: "INST",
                arg: ArgValue::Text(format!("{} {}", module, name)),
                pos: index,
                next: cursor,
            }
        }
        b'o' => simple_opcode("OBJ", index, cursor),
        0x81 => simple_opcode("NEWOBJ", index, cursor),
        0x92 => simple_opcode("NEWOBJ_EX", index, cursor),
        0x80 => ParsedOpcode {
            name: "PROTO",
            arg: ArgValue::Int(read_u8(payload, &mut cursor, limit)? as i64),
            pos: index,
            next: cursor,
        },
        b'.' => simple_opcode("STOP", index, cursor),
        0x95 => {
            let frame_len = read_u64_len(payload, &mut cursor, limit, index, "frame")?;
            ParsedOpcode {
                name: "FRAME",
                arg: ArgValue::UInt(frame_len),
                pos: index,
                next: cursor,
            }
        }
        b'P' => ParsedOpcode {
            name: "PERSID",
            arg: ArgValue::Text(read_line_text(payload, &mut cursor, limit)?),
            pos: index,
            next: cursor,
        },
        b'Q' => simple_opcode("BINPERSID", index, cursor),
        _ => {
            return Err(ParseError::new(format!(
                "at position {}, opcode {} unknown",
                index,
                python_byte_literal(op)
            )))
        }
    };
    Ok(parsed)
}

fn simple_opcode(name: &'static str, pos: usize, next: usize) -> ParsedOpcode {
    ParsedOpcode {
        name,
        arg: ArgValue::None,
        pos,
        next,
    }
}

fn python_byte_literal(byte: u8) -> String {
    match byte {
        b'\'' => "b\"'\"".to_string(),
        b'\\' => r#"b'\\'"#.to_string(),
        0x20..=0x7e => format!("b'{}'", char::from(byte)),
        _ => format!(r#"b'\x{byte:02x}'"#),
    }
}

fn read_u8(payload: &[u8], cursor: &mut usize, limit: usize) -> Result<u8, ParseError> {
    let bytes = read_fixed_width_bytes(payload, cursor, limit, 1, "uint1")?;
    Ok(bytes[0])
}

fn read_u16_le(payload: &[u8], cursor: &mut usize, limit: usize) -> Result<u16, ParseError> {
    let bytes = read_fixed_width_bytes(payload, cursor, limit, 2, "uint2")?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_i32_le(payload: &[u8], cursor: &mut usize, limit: usize) -> Result<i32, ParseError> {
    let bytes = read_fixed_width_bytes(payload, cursor, limit, 4, "int4")?;
    Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u32_le(payload: &[u8], cursor: &mut usize, limit: usize) -> Result<u32, ParseError> {
    let bytes = read_fixed_width_bytes(payload, cursor, limit, 4, "uint4")?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_le(payload: &[u8], cursor: &mut usize, limit: usize) -> Result<u64, ParseError> {
    let bytes = read_fixed_width_bytes(payload, cursor, limit, 8, "uint8")?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_u64_len(
    payload: &[u8],
    cursor: &mut usize,
    limit: usize,
    index: usize,
    read_kind: &'static str,
) -> Result<usize, ParseError> {
    usize::try_from(read_u64_le(payload, cursor, limit)?).map_err(|_| {
        ParseError::new(format!("pickle opcode {read_kind} length overflow")).at(index)
    })
}

fn read_fixed_width_bytes(
    payload: &[u8],
    cursor: &mut usize,
    limit: usize,
    len: usize,
    read_kind: &'static str,
) -> Result<Vec<u8>, ParseError> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| ParseError::new("pickle opcode length overflow").at(*cursor))?;
    if end > limit || end > payload.len() {
        return Err(ParseError::not_enough_fixed_width(
            read_kind,
            limit.min(payload.len()),
        ));
    }
    let value = payload[*cursor..end].to_vec();
    *cursor = end;
    Ok(value)
}

fn read_variable_bytes(
    payload: &[u8],
    cursor: &mut usize,
    limit: usize,
    len: usize,
    read_kind: &'static str,
) -> Result<Vec<u8>, ParseError> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| ParseError::new("pickle opcode length overflow").at(*cursor))?;
    if end > limit || end > payload.len() {
        let available = limit.min(payload.len()).saturating_sub(*cursor);
        return Err(ParseError::new(format!(
            "expected {len} bytes in a {read_kind}, but only {available} remain"
        ))
        .at(limit.min(payload.len())));
    }
    let value = payload[*cursor..end].to_vec();
    *cursor = end;
    Ok(value)
}

fn read_line_bytes(
    payload: &[u8],
    cursor: &mut usize,
    limit: usize,
) -> Result<Vec<u8>, ParseError> {
    read_line_bytes_kind(payload, cursor, limit, "stringnl")
}

fn read_line_bytes_kind(
    payload: &[u8],
    cursor: &mut usize,
    limit: usize,
    read_kind: &'static str,
) -> Result<Vec<u8>, ParseError> {
    let report_index = limit.min(payload.len());
    if *cursor >= limit {
        return Err(
            ParseError::new(format!("no newline found when trying to read {read_kind}"))
                .at(report_index),
        );
    }
    let search_end = limit.min(payload.len());
    let line_end = payload[*cursor..search_end]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|offset| *cursor + offset)
        .ok_or_else(|| {
            ParseError::new(format!("no newline found when trying to read {read_kind}"))
                .at(report_index)
        })?;
    let value = payload[*cursor..line_end].to_vec();
    *cursor = line_end + 1;
    Ok(value)
}

fn read_line_text(payload: &[u8], cursor: &mut usize, limit: usize) -> Result<String, ParseError> {
    Ok(String::from_utf8_lossy(&read_line_bytes(payload, cursor, limit)?).to_string())
}

fn read_line_raw_unicode(
    payload: &[u8],
    cursor: &mut usize,
    limit: usize,
) -> Result<String, ParseError> {
    Ok(decode_raw_unicode_escape(&read_line_bytes_kind(
        payload,
        cursor,
        limit,
        "unicodestringnl",
    )?))
}

fn parse_pickle_string_literal(value: &[u8]) -> String {
    let mut start = 0usize;
    let mut end = value.len();
    while start < end && value[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && value[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end.saturating_sub(start) >= 2 {
        let quote = value[start];
        if (quote == b'\'' || quote == b'"') && value[end - 1] == quote {
            return decode_python_string_escape(&value[start + 1..end - 1]);
        }
    }
    String::from_utf8_lossy(&value[start..end]).to_string()
}

fn decode_raw_unicode_escape(value: &[u8]) -> String {
    let mut decoded = String::new();
    let mut index = 0usize;
    while index < value.len() {
        if value[index] == b'\\' && index + 1 < value.len() {
            match value[index + 1] {
                b'u' if index + 6 <= value.len() => {
                    if let Some(ch) = decode_hex_codepoint(&value[index + 2..index + 6]) {
                        decoded.push(ch);
                        index += 6;
                        continue;
                    }
                }
                b'U' if index + 10 <= value.len() => {
                    if let Some(ch) = decode_hex_codepoint(&value[index + 2..index + 10]) {
                        decoded.push(ch);
                        index += 10;
                        continue;
                    }
                }
                _ => {}
            }
        }
        decoded.push(char::from(value[index]));
        index += 1;
    }
    decoded
}

fn decode_python_string_escape(value: &[u8]) -> String {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0usize;
    while index < value.len() {
        if value[index] != b'\\' || index + 1 >= value.len() {
            decoded.push(value[index]);
            index += 1;
            continue;
        }

        match value[index + 1] {
            b'\\' => {
                decoded.push(b'\\');
                index += 2;
            }
            b'\'' => {
                decoded.push(b'\'');
                index += 2;
            }
            b'"' => {
                decoded.push(b'"');
                index += 2;
            }
            b'a' => {
                decoded.push(0x07);
                index += 2;
            }
            b'b' => {
                decoded.push(0x08);
                index += 2;
            }
            b'f' => {
                decoded.push(0x0c);
                index += 2;
            }
            b'n' => {
                decoded.push(b'\n');
                index += 2;
            }
            b'r' => {
                decoded.push(b'\r');
                index += 2;
            }
            b't' => {
                decoded.push(b'\t');
                index += 2;
            }
            b'v' => {
                decoded.push(0x0b);
                index += 2;
            }
            b'x' if index + 4 <= value.len() => {
                if let Some(byte) = decode_hex_byte(value[index + 2], value[index + 3]) {
                    decoded.push(byte);
                    index += 4;
                } else {
                    decoded.push(value[index]);
                    index += 1;
                }
            }
            byte if (b'0'..=b'7').contains(&byte) => {
                let mut octal_value = 0u32;
                let mut octal_len = 0usize;
                while index + 1 + octal_len < value.len()
                    && octal_len < 3
                    && (b'0'..=b'7').contains(&value[index + 1 + octal_len])
                {
                    octal_value =
                        (octal_value * 8) + u32::from(value[index + 1 + octal_len] - b'0');
                    octal_len += 1;
                }
                decoded.push((octal_value & 0xff) as u8);
                index += 1 + octal_len;
            }
            other => {
                decoded.push(other);
                index += 2;
            }
        }
    }
    String::from_utf8_lossy(&decoded).to_string()
}

fn decode_hex_codepoint(value: &[u8]) -> Option<char> {
    let mut codepoint = 0u32;
    for byte in value {
        codepoint = codepoint.checked_mul(16)?;
        codepoint = codepoint.checked_add(u32::from(hex_value(*byte)?))?;
    }
    char::from_u32(codepoint)
}

fn decode_hex_byte(high: u8, low: u8) -> Option<u8> {
    Some((hex_value(high)? << 4) | hex_value(low)?)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
