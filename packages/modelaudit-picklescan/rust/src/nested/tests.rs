use super::*;

const TEST_MAX_NESTED_PICKLE_BYTES: usize = 2 * 1024 * 1024;

#[test]
fn encoded_prefix_gates_recognize_pickle_prefixes() {
    assert!(base64_prefix_has_pickle_prefix("gAR9Lg=="));
    assert!(hex_prefix_has_pickle_prefix("80047d2e"));
    assert!(hex_prefix_has_pickle_prefix(r"\x80\x04\x7d\x2e"));
    assert!(is_whole_encoded_pickle_literal("gAR9Lg=="));
    assert!(is_whole_encoded_pickle_literal("80047d2e"));
    assert!(is_whole_encoded_pickle_literal(r"\x80\x04\x7d\x2e"));
    assert!(!is_whole_encoded_pickle_literal("prefix-gAR9Lg=="));
}

#[test]
fn encoded_prefix_gates_recognize_binary_protocols_1_to_5() {
    for encoded in ["gAF9Lg==", "gAJ9Lg==", "gAN9Lg==", "gAR9Lg==", "gAV9Lg=="] {
        assert!(base64_prefix_has_pickle_prefix(encoded));
        let wrapped = format!("prefix-{encoded}-suffix");
        let windows = encoded_nested_literal_probe_windows(&wrapped, 64);
        assert!(windows.iter().any(|window| window.starts_with(encoded)));
    }

    for protocol in 1..=5 {
        let encoded = format!("800{protocol}7d2e");
        assert!(hex_prefix_has_pickle_prefix(&encoded));
        let wrapped = format!("prefix-{encoded}-suffix");
        let windows = encoded_nested_literal_probe_windows(&wrapped, 64);
        assert!(windows.iter().any(|window| window.starts_with(&encoded)));
    }
}

#[test]
fn pickle_prefix_recognizes_protocol1_binary_header() {
    let payload = b"\x80\x01}.";

    assert!(has_binary_pickle_prefix(payload));
    assert!(looks_like_pickle_payload(
        payload,
        TEST_MAX_NESTED_PICKLE_BYTES
    ));
    assert_eq!(
        pickle_payload_extent(payload, TEST_MAX_NESTED_PICKLE_BYTES),
        Some(payload.len())
    );
}

#[test]
fn encoded_prefix_gates_reject_benign_repeated_literals() {
    assert!(!base64_prefix_has_pickle_prefix("AAAAAAAAAAAAAAAA"));
    assert!(!hex_prefix_has_pickle_prefix("4141414141414141"));
    assert!(!encoded_literal_may_contain_pickle(&"A".repeat(1024)));
    assert!(
        decode_possible_encoded_pickle(&"A".repeat(1024), TEST_MAX_NESTED_PICKLE_BYTES).is_empty()
    );
    assert!(detect_oversized_encoded_pickle_prefixes(
        &"A".repeat(1024),
        TEST_MAX_NESTED_PICKLE_BYTES
    )
    .is_empty());
}

#[test]
fn oversized_base64_custom_global_name_uses_contiguous_structural_evidence() {
    let encoded = "Y2N1c3RvbW1vZHVsZQpBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQou";
    let max_nested_pickle_bytes = 64;

    assert!(encoded_literal_may_contain_pickle(encoded));
    assert!(base64_prefix_has_pickle_prefix(encoded));
    assert_eq!(
        detect_oversized_encoded_pickle_prefixes(encoded, max_nested_pickle_bytes),
        vec![("base64", 81)]
    );
}

#[test]
fn oversized_mixed_hex_custom_global_name_preserves_token_boundaries() {
    let encoded = format!(
        r"\x63{}{}0a2e",
        "637573746f6d6d6f64756c650a",
        "41".repeat(65)
    );

    assert_eq!(
        detect_oversized_encoded_pickle_prefixes(&encoded, 64),
        vec![("escaped_hex", 81)]
    );
}

#[test]
fn oversized_dangerous_global_like_prose_is_not_a_pickle() {
    let encoded = format!("636f730a{}0a706c61696e20666f6f7465720a", "41".repeat(65));

    assert!(detect_oversized_encoded_pickle_prefixes(&encoded, 64).is_empty());
}

#[test]
fn encoded_probe_windows_reject_benign_hexish_large_literals() {
    let value = format!("{}os.system('id'){}", "A".repeat(4096), "B".repeat(4096));

    assert!(encoded_nested_literal_probe_windows(&value, 4096).is_empty());
}

#[test]
fn encoded_probe_windows_keep_embedded_encoded_pickle_candidates() {
    let value = format!("{}gAR9Lg=={}", "A".repeat(128), "B".repeat(128));
    let windows = encoded_nested_literal_probe_windows(&value, 64);

    assert!(encoded_literal_may_contain_pickle(&value));
    assert!(windows.iter().any(|window| window.starts_with("gAR9Lg==")));
}

#[test]
fn encoded_probe_windows_report_limit_after_decoys_exhaust_cap() {
    let mut value = String::new();
    for index in 0..MAX_NESTED_PAYLOAD_PROBES {
        value.push_str(&format!("gAR9Lg==-decoy-{index}|"));
    }
    let hidden_payload = "Y29zCnN5c3RlbQopUi4";
    value.push_str(hidden_payload);
    value.push_str(&"A".repeat(ENCODED_LITERAL_PROBE_CHARS + 1));

    let probed = encoded_nested_literal_probe_windows_with_limit(&value, 64);

    assert!(probed.limit_exceeded);
    assert_eq!(probed.limit_exceeded_encoding, Some("base64"));
    assert_eq!(probed.windows.len(), MAX_NESTED_PAYLOAD_PROBES);
    assert!(!probed
        .windows
        .iter()
        .any(|window| window.starts_with(hidden_payload)));
}

#[test]
fn encoded_probe_windows_skip_mid_scan_for_whole_encoded_literals() {
    for value in ["gAR9Lg==", "80047d2e", r"\x80\x04\x7d\x2e"] {
        let windows = encoded_nested_literal_probe_windows(value, 64);

        assert_eq!(windows, vec![value.to_string()]);
    }
}

#[test]
fn encoded_probe_windows_bound_mid_literal_scan_cost() {
    let within_bound = format!(
        "{}gAR9Lg=={}",
        "A".repeat(MAX_ENCODED_LITERAL_MID_SCAN_BYTES.saturating_sub(16)),
        "B".repeat(128)
    );
    let within_windows = encoded_nested_literal_probe_windows(&within_bound, 64);
    assert!(within_windows
        .iter()
        .any(|window| window.starts_with("gAR9Lg==")));

    let beyond_bound = format!(
        "{}gAR9Lg=={}",
        "A".repeat(MAX_ENCODED_LITERAL_MID_SCAN_BYTES + 16),
        "B".repeat(ENCODED_LITERAL_PROBE_CHARS + 1)
    );
    let beyond_windows = encoded_nested_literal_probe_windows(&beyond_bound, 64);
    assert!(!beyond_windows
        .iter()
        .any(|window| window.starts_with("gAR9Lg==")));
    assert!(encoded_nested_literal_probe_coverage_incomplete(
        &beyond_bound
    ));
}

#[test]
fn encoded_probe_coverage_treats_trimmed_whole_literals_as_complete() {
    let whole_literal = format!("gAR9{}\n", "A".repeat(MAX_ENCODED_LITERAL_MID_SCAN_BYTES));

    assert!(!encoded_nested_literal_probe_coverage_incomplete(
        &whole_literal
    ));
}

#[test]
fn encoded_probe_windows_keep_protocol0_embedded_encoded_pickle_candidates() {
    let value = format!("{}Y29zCnN5c3RlbQopUi4={}", "A".repeat(128), "B".repeat(128));
    let windows = encoded_nested_literal_probe_windows(&value, 64);

    assert!(windows
        .iter()
        .any(|window| window.starts_with("Y29zCnN5c3RlbQopUi4=")));
}

#[test]
fn wrapped_base64_nested_literals_ignore_comment_leaders() {
    let value = "# this is doc\n# Y29zCnN5\n# c3RlbQopUi4=\n# more";
    let decoded = decode_possible_encoded_pickle(value, TEST_MAX_NESTED_PICKLE_BYTES);

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].encoding, "base64");
    assert_eq!(decoded[0].payload, b"cos\nsystem\n)R.");
    assert!(!decoded[0].analysis_incomplete);
}

#[test]
fn encoded_nested_literals_keep_later_decoded_payloads() {
    let decoded =
        decode_possible_encoded_pickle("gAR9LmNvcwpzeXN0ZW0KKVIu", TEST_MAX_NESTED_PICKLE_BYTES);

    assert!(decoded
        .iter()
        .any(|candidate| candidate.encoding == "base64" && candidate.payload == b"\x80\x04}."));
    assert!(decoded.iter().any(
        |candidate| candidate.encoding == "base64" && candidate.payload == b"cos\nsystem\n)R."
    ));
}

#[test]
fn decoded_payloads_preserve_protocol0_operand_limit_failures() {
    let mut payload = b"cos\nsystem\n(S'".to_vec();
    payload.resize(
        payload.len() + crate::opcode::MAX_PROTOCOL0_LINE_OPERAND_BYTES,
        b'A',
    );
    payload.extend_from_slice(b"'\ntR.");

    let decoded = decoded_pickle_payloads(&payload, payload.len() + 16);

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].0, payload);
    assert!(decoded[0].1);
}

#[test]
fn decoded_payloads_preserve_protocol0_operand_limit_after_inst() {
    let mut payload = b"(ios\nsystem\n(S'".to_vec();
    payload.resize(
        payload.len() + crate::opcode::MAX_PROTOCOL0_LINE_OPERAND_BYTES,
        b'A',
    );
    payload.extend_from_slice(b"'\ntR.");

    let decoded = decoded_pickle_payloads(&payload, payload.len() + 16);

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].0, payload);
    assert!(decoded[0].1);
}

#[test]
fn decoded_payloads_ignore_unstructured_protocol0_operand_limit_failures() {
    let mut payload = b"S'".to_vec();
    payload.resize(
        payload.len() + crate::opcode::MAX_PROTOCOL0_LINE_OPERAND_BYTES + 1,
        b'A',
    );
    let operand_end = payload.len();

    assert!(decoded_pickle_payloads(&payload, payload.len() + 16).is_empty());
    let error = pickle_payload_extent_result(&payload, payload.len() + 16)
        .expect_err("overlong protocol 0 string should preserve its parse error");
    assert!(!error.is_structured_protocol0_line_operand_limit());

    payload.extend_from_slice(b"\n.");
    let error = pickle_payload_extent_result(&payload, payload.len() + 16)
        .expect_err("benign suffix should not promote an overlong data operand");
    assert!(!error.is_structured_protocol0_line_operand_limit());

    payload.truncate(operand_end);
    payload.extend_from_slice(b"'\nrandom benign footer\n");
    let error = pickle_payload_extent_result(&payload, payload.len() + 16)
        .expect_err("opcode-like letters in prose should not promote an overlong data operand");
    assert!(!error.is_structured_protocol0_line_operand_limit());

    payload.truncate(operand_end);
    payload.extend_from_slice(b"'\ncfoo\nbar");
    let error = pickle_payload_extent_result(&payload, payload.len() + 16)
        .expect_err("an incomplete global suffix is not execution evidence");
    assert!(!error.is_structured_protocol0_line_operand_limit());
}

#[test]
fn protocol0_operand_limit_preserves_dangerous_suffix_evidence() {
    let mut payload = b"S'".to_vec();
    payload.resize(
        payload.len() + crate::opcode::MAX_PROTOCOL0_LINE_OPERAND_BYTES + 1,
        b'A',
    );
    payload.extend_from_slice(b"'\n0cos\nsystem\n)R.");

    let error = pickle_payload_extent_result(&payload, payload.len() + 16)
        .expect_err("dangerous suffix should preserve the operand-limit failure");
    assert!(error.is_structured_protocol0_line_operand_limit());
    let decoded = decoded_pickle_payloads(&payload, payload.len() + 16);
    assert_eq!(decoded.len(), 1);
    assert!(decoded[0].1);
}

#[test]
fn protocol0_global_and_inst_name_limits_preserve_opcode_evidence() {
    for prefix in [b"cos\n".as_slice(), b"ios\n".as_slice()] {
        let mut payload = prefix.to_vec();
        payload.resize(
            payload.len() + crate::opcode::MAX_PROTOCOL0_LINE_OPERAND_BYTES + 1,
            b'A',
        );
        payload.extend_from_slice(b"\n.");

        assert!(has_pickle_prefix(&payload));
        let error = pickle_payload_extent_result(&payload, payload.len() + 16)
            .expect_err("overlong GLOBAL or INST name should preserve its parse failure");
        assert!(error.is_structured_protocol0_line_operand_limit());
    }
}

#[test]
fn truncated_global_and_inst_names_preserve_opcode_evidence_before_operand_limit() {
    for prefix in [b"cos\n".as_slice(), b"ios\n".as_slice()] {
        let mut payload = prefix.to_vec();
        payload.resize(TEST_MAX_NESTED_PICKLE_BYTES, b'A');
        payload.extend_from_slice(b"\n.");

        assert!(has_pickle_prefix(&payload));
        assert!(truncated_pickle_prefix_requires_fail_closed(&payload));
    }
}

#[test]
fn truncated_global_name_prefix_requires_a_terminator_before_the_parser_cap() {
    let mut benign = b"config\n".to_vec();
    benign.resize(TEST_MAX_NESTED_PICKLE_BYTES + 1, b'A');

    assert!(!has_pickle_prefix(&benign));
    assert!(!truncated_pickle_prefix_requires_fail_closed(&benign));

    benign.extend_from_slice(b"\nplain footer\n");
    assert!(!has_pickle_prefix(&benign));
    assert!(!truncated_pickle_prefix_requires_fail_closed(&benign));
}

#[test]
fn structured_execution_setup_survives_a_truncated_protocol0_line() {
    let mut payload = b"Vos\nVsystem\n\x93p0\n0(S'true'\ntp1\n0S'".to_vec();
    payload.resize(TEST_MAX_NESTED_PICKLE_BYTES, b'A');

    let error = pickle_payload_extent_result(&payload, payload.len())
        .expect_err("structured execution before a clipped line should remain fail-closed");

    assert!(error.is_structured_protocol0_line_operand_truncated());
}

#[test]
fn protocol0_operand_limit_requires_prior_structured_opcode() {
    let mut payload = b"cos\nsystem\n(S'".to_vec();
    payload.resize(
        payload.len() + crate::opcode::MAX_PROTOCOL0_LINE_OPERAND_BYTES,
        b'A',
    );

    let error = pickle_payload_extent_result(&payload, payload.len() + 16)
        .expect_err("overlong nested operand should preserve its parse error");
    assert!(error.is_structured_protocol0_line_operand_limit());
}

#[test]
fn protocol0_operand_limit_tracks_structured_evidence_beyond_prefix_probe() {
    let mut payload = b"(NNNNcos\nsystem\n(S'".to_vec();
    payload.resize(
        payload.len() + crate::opcode::MAX_PROTOCOL0_LINE_OPERAND_BYTES,
        b'A',
    );

    let error = pickle_payload_extent_result(&payload, payload.len() + 16)
        .expect_err("structured evidence after setup opcodes should survive the operand cap");
    assert!(error.is_structured_protocol0_line_operand_limit());
}

#[test]
fn encoded_probe_windows_keep_protocol0_escaped_hex_pickle_candidates() {
    for encoded in [
        r"\x28\x64\x2e",
        r"\x49\x31\x0a\x2e",
        r"\x53\x27\x78\x27\x0a\x2e",
        r"\x56\x78\x0a\x2e",
        r"\x63\x6f\x73\x0a\x73\x79\x73\x74\x65\x6d\x0a\x2e",
        r"\X63\X6f\X73\X0a\X73\X79\X73\X74\X65\X6d\X0a\X2e",
        r"\x64\x2e",
        r"\x6c\x2e",
        r"\x69\x6f\x73\x0a\x73\x79\x73\x74\x65\x6d\x0a\x2e",
    ] {
        let value = format!("prefix-{encoded}-suffix");
        let windows = encoded_nested_literal_probe_windows(&value, 64);

        assert!(
            windows.iter().any(|window| window.starts_with(encoded)),
            "missing escaped-hex candidate window for {encoded}"
        );
    }
}

#[test]
fn execution_opcode_detection_distinguishes_structural_nested_payloads() {
    assert!(!has_execution_opcode(b"\x80\x04}q\x00."));
    assert!(has_execution_opcode(
        b"\x80\x04\x8c\x08builtins\x94\x8c\x05print\x94\x93\x8c\x02hi\x85R."
    ));
    assert!(has_execution_opcode(b"\x80\x04cos\nsystem\nPfake_id\n."));
    assert!(looks_like_pickle_payload(
        b"\x80\x04cos\nsystem\nPfake_id\n.",
        TEST_MAX_NESTED_PICKLE_BYTES
    ));
    assert!(!has_execution_opcode(
        b"i\x69\xb2\x09\x48\xbe\x7d\x02\x6b\x23\x5f\xe0\xf7\x0a\x8a\x5c\x77"
    ));
    assert!(!has_structured_execution_prefix(b"dom benign footer\n"));
    assert!(has_structured_execution_prefix(b"cos\nsystem\n)R."));
}

#[test]
fn truncated_prefix_fail_closed_ignores_structural_protocol0_near_matches() {
    assert!(truncated_pickle_prefix_requires_fail_closed(
        b"\x80\x04]K\x01aK\x02aK\x03a"
    ));
    assert!(truncated_pickle_prefix_requires_fail_closed(
        b"\x80\x04\x95\x1f\x00\x00\x00\x00"
    ));
    assert!(!truncated_pickle_prefix_requires_fail_closed(
        b"\x80\x04AAAAAAAA"
    ));
    assert!(!truncated_pickle_prefix_requires_fail_closed(
        b"\x80\x04\xff\xff\xff\xff"
    ));
    assert!(truncated_pickle_prefix_requires_fail_closed(
        b"cos\nsystem\nAAAAAAAA"
    ));
    assert!(truncated_pickle_prefix_requires_fail_closed(
        b"ios\nsystem\nAAAAAAAA"
    ));
    assert!(!truncated_pickle_prefix_requires_fail_closed(
        b"i\x69\xb2\x09\x48\xbe\x7d\x02\x6b\x23\x5f\xe0\xf7\x0a\x8a\x5c\x77"
    ));
    assert!(!truncated_pickle_prefix_requires_fail_closed(
        b"inner\x94\x8c\x04data\x94s.BBBBB"
    ));
    assert!(!truncated_pickle_prefix_requires_fail_closed(
        b"S'not-a-full-pickle'\nAAAA"
    ));
    assert!(!truncated_pickle_prefix_requires_fail_closed(
        b"Vnot-a-full-pickle\nAAAA"
    ));
    assert!(!truncated_pickle_prefix_requires_fail_closed(
        b"}q\x00BBBBBBBB"
    ));
}

#[test]
fn stack_validation_models_batch_container_mutation_and_protocol5_buffers() {
    assert!(!looks_like_pickle_payload(
        b"\x80\x04](ea.",
        TEST_MAX_NESTED_PICKLE_BYTES
    ));
    assert!(looks_like_pickle_payload(
        b"\x80\x05\x97.",
        TEST_MAX_NESTED_PICKLE_BYTES
    ));
}

#[test]
fn byte_bounded_string_windows_preserve_utf8_boundaries() {
    assert_eq!(take_bytes_str("abc", 2), "ab");
    assert_eq!(take_bytes_str("a\u{2603}b", 2), "a");
    assert_eq!(take_bytes_str("a\u{2603}b", 4), "a\u{2603}");
}
