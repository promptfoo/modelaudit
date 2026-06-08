use std::borrow::Cow;

pub(crate) const MAX_PROTOCOL0_LINE_OPERAND_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub(crate) enum ArgValue {
    None,
    Int(i64),
    UInt(usize),
    Text(String),
    DecodedString { text: String, bytes: Vec<u8> },
    TextSpan { start: usize, end: usize },
    Bytes { start: usize, end: usize },
    Global { module: String, name: String },
}

impl ArgValue {
    pub(crate) fn as_i64(&self) -> Option<i64> {
        match self {
            ArgValue::Int(value) => Some(*value),
            ArgValue::UInt(value) => i64::try_from(*value).ok(),
            ArgValue::Text(value) => value.parse::<i64>().ok(),
            ArgValue::DecodedString { text, .. } => text.parse::<i64>().ok(),
            _ => None,
        }
    }

    pub(crate) fn byte_span(&self, payload_len: usize) -> Option<(usize, usize)> {
        match self {
            ArgValue::Bytes { start, end } if start <= end && *end <= payload_len => {
                Some((*start, *end))
            }
            _ => None,
        }
    }

    pub(crate) fn raw_bytes<'payload>(
        &'payload self,
        payload: &'payload [u8],
    ) -> Option<Cow<'payload, [u8]>> {
        match self {
            ArgValue::Bytes { start, end } if start <= end && *end <= payload.len() => {
                Some(Cow::Borrowed(&payload[*start..*end]))
            }
            ArgValue::DecodedString { bytes, .. } => Some(Cow::Borrowed(bytes.as_slice())),
            _ => None,
        }
    }

    pub(crate) fn text<'payload>(&self, payload: &'payload [u8]) -> Cow<'payload, str> {
        match self {
            ArgValue::Text(value) => Cow::Owned(value.clone()),
            ArgValue::DecodedString { text, .. } => Cow::Owned(text.clone()),
            ArgValue::TextSpan { start, end } | ArgValue::Bytes { start, end }
                if start <= end && *end <= payload.len() =>
            {
                String::from_utf8_lossy(&payload[*start..*end])
            }
            ArgValue::Int(value) => Cow::Owned(value.to_string()),
            ArgValue::UInt(value) => Cow::Owned(value.to_string()),
            ArgValue::Global { module, name } => Cow::Owned(format!("{module} {name}")),
            ArgValue::None => Cow::Borrowed(""),
            _ => Cow::Borrowed(""),
        }
    }

    pub(crate) fn global_parts(&self, payload: &[u8]) -> (String, String) {
        match self {
            ArgValue::Global { module, name } => (module.clone(), name.clone()),
            ArgValue::Text(_)
            | ArgValue::DecodedString { .. }
            | ArgValue::TextSpan { .. }
            | ArgValue::Bytes { .. } => {
                let value = self.text(payload);
                let mut parts = value.splitn(2, ' ');
                let module = parts.next().unwrap_or_default().to_string();
                let name = parts.next().unwrap_or_default().to_string();
                (module, name)
            }
            _ => ("".to_string(), "".to_string()),
        }
    }

    pub(crate) fn coerce_text(&self, payload: &[u8]) -> String {
        self.text(payload).into_owned()
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
    kind: ParseErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseErrorKind {
    Generic,
    Protocol0LineOperandTruncated,
    Protocol0LineOperandLimit,
}

impl ParseError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exception_type: "ValueError",
            report_index: None,
            kind: ParseErrorKind::Generic,
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
            kind: ParseErrorKind::Generic,
        }
    }

    fn protocol0_line_operand_limit(read_kind: &'static str, index: usize) -> Self {
        Self {
            message: format!(
                "{read_kind} protocol 0 line operand exceeds {MAX_PROTOCOL0_LINE_OPERAND_BYTES} bytes"
            ),
            exception_type: "ValueError",
            report_index: Some(index),
            kind: ParseErrorKind::Protocol0LineOperandLimit,
        }
    }

    fn protocol0_line_operand_truncated(read_kind: &'static str, index: usize) -> Self {
        Self {
            message: format!("no newline found when trying to read {read_kind}"),
            exception_type: "ValueError",
            report_index: Some(index),
            kind: ParseErrorKind::Protocol0LineOperandTruncated,
        }
    }

    pub(crate) fn is_protocol0_line_operand_limit(&self) -> bool {
        self.kind == ParseErrorKind::Protocol0LineOperandLimit
    }

    pub(crate) fn is_protocol0_line_operand_truncated(&self) -> bool {
        self.kind == ParseErrorKind::Protocol0LineOperandTruncated
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
            let (start, end) = read_fixed_width_span(payload, &mut cursor, limit, len, "long1")?;
            ParsedOpcode {
                name: "LONG1",
                arg: ArgValue::Bytes { start, end },
                pos: index,
                next: cursor,
            }
        }
        0x8b => {
            let len = read_u32_le(payload, &mut cursor, limit)? as usize;
            let (start, end) = read_fixed_width_span(payload, &mut cursor, limit, len, "long4")?;
            ParsedOpcode {
                name: "LONG4",
                arg: ArgValue::Bytes { start, end },
                pos: index,
                next: cursor,
            }
        }
        b'S' => {
            let literal = read_line_bytes(payload, &mut cursor, limit)?;
            let bytes = parse_pickle_string_literal_bytes(&literal);
            ParsedOpcode {
                name: "STRING",
                arg: ArgValue::DecodedString {
                    text: String::from_utf8_lossy(&bytes).to_string(),
                    bytes,
                },
                pos: index,
                next: cursor,
            }
        }
        b'T' => {
            let len = read_u32_le(payload, &mut cursor, limit)? as usize;
            let (start, end) = read_variable_span(payload, &mut cursor, limit, len, "string4")?;
            ParsedOpcode {
                name: "BINSTRING",
                arg: ArgValue::Bytes { start, end },
                pos: index,
                next: cursor,
            }
        }
        b'U' => {
            let len = read_u8(payload, &mut cursor, limit)? as usize;
            let (start, end) = read_variable_span(payload, &mut cursor, limit, len, "string1")?;
            ParsedOpcode {
                name: "SHORT_BINSTRING",
                arg: ArgValue::Bytes { start, end },
                pos: index,
                next: cursor,
            }
        }
        b'B' => {
            let len = read_u32_le(payload, &mut cursor, limit)? as usize;
            let (start, end) = read_variable_span(payload, &mut cursor, limit, len, "bytes4")?;
            ParsedOpcode {
                name: "BINBYTES",
                arg: ArgValue::Bytes { start, end },
                pos: index,
                next: cursor,
            }
        }
        b'C' => {
            let len = read_u8(payload, &mut cursor, limit)? as usize;
            let (start, end) = read_variable_span(payload, &mut cursor, limit, len, "bytes1")?;
            ParsedOpcode {
                name: "SHORT_BINBYTES",
                arg: ArgValue::Bytes { start, end },
                pos: index,
                next: cursor,
            }
        }
        0x8e => {
            let len = read_u64_len(payload, &mut cursor, limit, index, "bytes8")?;
            let (start, end) = read_variable_span(payload, &mut cursor, limit, len, "bytes8")?;
            ParsedOpcode {
                name: "BINBYTES8",
                arg: ArgValue::Bytes { start, end },
                pos: index,
                next: cursor,
            }
        }
        0x96 => {
            let len = read_u64_len(payload, &mut cursor, limit, index, "bytearray8")?;
            let (start, end) = read_variable_span(payload, &mut cursor, limit, len, "bytearray8")?;
            ParsedOpcode {
                name: "BYTEARRAY8",
                arg: ArgValue::Bytes { start, end },
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
            let (start, end) =
                read_variable_span(payload, &mut cursor, limit, len, "unicodestring1")?;
            ParsedOpcode {
                name: "SHORT_BINUNICODE",
                arg: ArgValue::TextSpan { start, end },
                pos: index,
                next: cursor,
            }
        }
        b'X' => {
            let len = read_u32_le(payload, &mut cursor, limit)? as usize;
            let (start, end) =
                read_variable_span(payload, &mut cursor, limit, len, "unicodestring4")?;
            ParsedOpcode {
                name: "BINUNICODE",
                arg: ArgValue::TextSpan { start, end },
                pos: index,
                next: cursor,
            }
        }
        0x8d => {
            let len = read_u64_len(payload, &mut cursor, limit, index, "unicodestring8")?;
            let (start, end) =
                read_variable_span(payload, &mut cursor, limit, len, "unicodestring8")?;
            ParsedOpcode {
                name: "BINUNICODE8",
                arg: ArgValue::TextSpan { start, end },
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
            arg: {
                let (start, end) = read_fixed_width_span(payload, &mut cursor, limit, 8, "float8")?;
                ArgValue::Bytes { start, end }
            },
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
                arg: ArgValue::Global { module, name },
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
                arg: ArgValue::Global { module, name },
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
    let (start, end) = read_fixed_width_span(payload, cursor, limit, 1, "uint1")?;
    Ok(payload[start..end][0])
}

fn read_u16_le(payload: &[u8], cursor: &mut usize, limit: usize) -> Result<u16, ParseError> {
    let (start, end) = read_fixed_width_span(payload, cursor, limit, 2, "uint2")?;
    let bytes = &payload[start..end];
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_i32_le(payload: &[u8], cursor: &mut usize, limit: usize) -> Result<i32, ParseError> {
    let (start, end) = read_fixed_width_span(payload, cursor, limit, 4, "int4")?;
    let bytes = &payload[start..end];
    Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u32_le(payload: &[u8], cursor: &mut usize, limit: usize) -> Result<u32, ParseError> {
    let (start, end) = read_fixed_width_span(payload, cursor, limit, 4, "uint4")?;
    let bytes = &payload[start..end];
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_le(payload: &[u8], cursor: &mut usize, limit: usize) -> Result<u64, ParseError> {
    let (start, end) = read_fixed_width_span(payload, cursor, limit, 8, "uint8")?;
    let bytes = &payload[start..end];
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

fn read_fixed_width_span(
    payload: &[u8],
    cursor: &mut usize,
    limit: usize,
    len: usize,
    read_kind: &'static str,
) -> Result<(usize, usize), ParseError> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| ParseError::new("pickle opcode length overflow").at(*cursor))?;
    if end > limit || end > payload.len() {
        return Err(ParseError::not_enough_fixed_width(
            read_kind,
            limit.min(payload.len()),
        ));
    }
    let start = *cursor;
    *cursor = end;
    Ok((start, end))
}

fn read_variable_span(
    payload: &[u8],
    cursor: &mut usize,
    limit: usize,
    len: usize,
    read_kind: &'static str,
) -> Result<(usize, usize), ParseError> {
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
    let start = *cursor;
    *cursor = end;
    Ok((start, end))
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
        return Err(ParseError::protocol0_line_operand_truncated(
            read_kind,
            report_index,
        ));
    }
    let payload_end = limit.min(payload.len());
    let search_end =
        payload_end.min((*cursor).saturating_add(MAX_PROTOCOL0_LINE_OPERAND_BYTES + 1));
    let line_end = payload[*cursor..search_end]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|offset| *cursor + offset)
        .ok_or_else(|| {
            if payload_end.saturating_sub(*cursor) > MAX_PROTOCOL0_LINE_OPERAND_BYTES {
                ParseError::protocol0_line_operand_limit(read_kind, search_end)
            } else {
                ParseError::protocol0_line_operand_truncated(read_kind, report_index)
            }
        })?;
    if line_end.saturating_sub(*cursor) > MAX_PROTOCOL0_LINE_OPERAND_BYTES {
        return Err(ParseError::protocol0_line_operand_limit(
            read_kind, line_end,
        ));
    }
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

pub(crate) fn parse_pickle_string_literal_bytes(value: &[u8]) -> Vec<u8> {
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
    value[start..end].to_vec()
}

pub(crate) fn decode_raw_unicode_escape(value: &[u8]) -> String {
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

fn decode_python_string_escape(value: &[u8]) -> Vec<u8> {
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
    decoded
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_global_operands_and_positions() {
        let payload = b"cos\nsystem\n.";
        let opcode = parse_opcode(payload, 0, payload.len()).expect("GLOBAL opcode");

        assert_eq!(opcode.name, "GLOBAL");
        assert_eq!(opcode.pos, 0);
        assert_eq!(opcode.next, 11);
        assert_eq!(
            opcode.arg.global_parts(payload),
            ("os".to_string(), "system".to_string())
        );
    }

    #[test]
    fn parse_global_operands_preserve_spaces() {
        let payload = b"imodule with space\ncallable name\n.";
        let opcode = parse_opcode(payload, 0, payload.len()).expect("INST opcode");

        assert_eq!(opcode.name, "INST");
        assert_eq!(
            opcode.arg.global_parts(payload),
            ("module with space".to_string(), "callable name".to_string())
        );
    }

    #[test]
    fn parse_variable_bytes_as_payload_spans() {
        let payload = b"C\x03abc.";
        let opcode = parse_opcode(payload, 0, payload.len()).expect("SHORT_BINBYTES opcode");

        assert_eq!(opcode.name, "SHORT_BINBYTES");
        assert_eq!(opcode.arg.byte_span(payload.len()), Some((2, 5)));
        assert_eq!(opcode.arg.text(payload).as_ref(), "abc");
    }

    #[test]
    fn parse_long_integer_operands_as_payload_spans() {
        let long1_payload = b"\x8a\x02\x01\x00.";
        let long1 = parse_opcode(long1_payload, 0, long1_payload.len()).expect("LONG1 opcode");
        assert_eq!(long1.name, "LONG1");
        assert_eq!(long1.arg.byte_span(long1_payload.len()), Some((2, 4)));
        assert_eq!(long1.next, 4);

        let long4_payload = b"\x8b\x02\x00\x00\x00\xff\x00.";
        let long4 = parse_opcode(long4_payload, 0, long4_payload.len()).expect("LONG4 opcode");
        assert_eq!(long4.name, "LONG4");
        assert_eq!(long4.arg.byte_span(long4_payload.len()), Some((5, 7)));
        assert_eq!(long4.next, 7);
    }

    #[test]
    fn parse_oversized_long4_reports_bounded_value_error() {
        let payload = b"\x8b\xff\xff\xff\xff.";
        let error = match parse_opcode(payload, 0, payload.len()) {
            Ok(_) => panic!("oversized LONG4 should fail"),
            Err(error) => error,
        };

        assert_eq!(error.exception_type, "ValueError");
        assert!(error.message.contains("long4"));
        assert_eq!(error.report_index, Some(payload.len()));
    }

    #[test]
    fn parse_protocol0_string_escapes() {
        let payload = b"S'\\x6f\\163\\n'\n.";
        let opcode = parse_opcode(payload, 0, payload.len()).expect("STRING opcode");

        assert_eq!(opcode.name, "STRING");
        assert_eq!(opcode.arg.text(payload).as_ref(), "os\n");
    }

    #[test]
    fn parse_protocol0_line_operand_accepts_exact_limit() {
        let mut payload = Vec::with_capacity(MAX_PROTOCOL0_LINE_OPERAND_BYTES + 3);
        payload.extend_from_slice(b"S'");
        payload.resize(payload.len() + MAX_PROTOCOL0_LINE_OPERAND_BYTES - 2, b'a');
        payload.extend_from_slice(b"'\n.");

        let opcode = parse_opcode(&payload, 0, payload.len()).expect("STRING at line limit");

        assert_eq!(opcode.name, "STRING");
        assert_eq!(opcode.next, MAX_PROTOCOL0_LINE_OPERAND_BYTES + 2);
    }

    #[test]
    fn parse_protocol0_line_operand_rejects_over_limit_before_copy() {
        let mut payload = Vec::with_capacity(MAX_PROTOCOL0_LINE_OPERAND_BYTES + 4);
        payload.extend_from_slice(b"S'");
        payload.resize(payload.len() + MAX_PROTOCOL0_LINE_OPERAND_BYTES - 1, b'a');
        payload.extend_from_slice(b"'\n.");

        let error = match parse_opcode(&payload, 0, payload.len()) {
            Ok(_) => panic!("overlong protocol 0 line operand should fail"),
            Err(error) => error,
        };

        assert_eq!(error.exception_type, "ValueError");
        assert!(error.is_protocol0_line_operand_limit());
        assert!(error.message.contains("protocol 0 line operand exceeds"));
        assert_eq!(
            error.report_index,
            Some(MAX_PROTOCOL0_LINE_OPERAND_BYTES + 2)
        );
    }

    #[test]
    fn parse_truncated_frame_reports_value_error() {
        let error = match parse_opcode(b"\x95\x01", 0, 2) {
            Ok(_) => panic!("truncated FRAME should fail"),
            Err(error) => error,
        };

        assert_eq!(error.exception_type, "ValueError");
        assert!(error.message.contains("not enough data"));
        assert_eq!(error.report_index, Some(2));
    }
}
