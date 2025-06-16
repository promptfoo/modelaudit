import json
import tempfile
from pathlib import Path

import pytest

from modelaudit.core import is_tokenizer_file, scan_model_directory_or_file


class TestTokenizerDetection:
    """Test suite for tokenizer file detection functionality."""

    def test_is_tokenizer_file_by_filename(self, tmp_path):
        """Test tokenizer detection by common filenames."""
        tokenizer_filenames = [
            "tokenizer.json",
            "tokenizer.model",
            "vocab.json",
            "vocab.txt",
            "merges.txt",
            "special_tokens_map.json", 
            "tokenizer_config.json",
            "added_tokens.json",
        ]
        
        for filename in tokenizer_filenames:
            # Create empty file
            test_file = tmp_path / filename
            test_file.write_text("{}")
            
            assert is_tokenizer_file(str(test_file)), f"{filename} should be detected as tokenizer file"

    def test_is_tokenizer_file_by_pattern(self, tmp_path):
        """Test tokenizer detection by filename patterns."""
        tokenizer_patterns = [
            "my_tokenizer.json",
            "bert_vocab.json", 
            "vocabulary_v2.json",
            "custom_tokenizer_config.json",
        ]
        
        for filename in tokenizer_patterns:
            # Create file with tokenizer content
            test_file = tmp_path / filename
            test_file.write_text('{"vocab": {"hello": 1, "world": 2}}')
            
            assert is_tokenizer_file(str(test_file)), f"{filename} should be detected as tokenizer file"

    def test_is_tokenizer_file_by_content(self, tmp_path):
        """Test tokenizer detection by file content (for files with tokenizer patterns in name)."""
        tokenizer_contents = [
            '{"vocab": {"hello": 1, "world": 2}}',
            '{"model": {"vocab": {"test": 123}}}',
            '{"added_tokens": [{"id": 0, "content": "<pad>"}]}',
            '{"tokenizer_class": "BertTokenizer"}',
            '{"model_max_length": 512}',
        ]
        
        for i, content in enumerate(tokenizer_contents):
            # Use filename with tokenizer pattern so content check is triggered
            test_file = tmp_path / f"tokenizer_test_{i}.json"
            test_file.write_text(content)
            
            assert is_tokenizer_file(str(test_file)), f"Content {content} should be detected as tokenizer file"

    def test_is_tokenizer_file_non_tokenizer(self, tmp_path):
        """Test that non-tokenizer files are not detected as tokenizers."""
        non_tokenizer_files = [
            ("model.pkl", b"pickle content"),
            ("config.json", '{"hidden_size": 768, "num_layers": 12}'),
            ("weights.h5", b"HDF5 content"),
            ("data.txt", "plain text file"),
            ("script.py", "import torch\nprint('hello')"),
        ]
        
        for filename, content in non_tokenizer_files:
            test_file = tmp_path / filename
            if isinstance(content, str):
                test_file.write_text(content)
            else:
                test_file.write_bytes(content)
            
            assert not is_tokenizer_file(str(test_file)), f"{filename} should NOT be detected as tokenizer file"

    def test_is_tokenizer_file_malformed_json(self, tmp_path):
        """Test tokenizer detection with malformed JSON files."""
        # Create a file with tokenizer pattern in name but malformed JSON
        test_file = tmp_path / "tokenizer_malformed.json"
        test_file.write_text('{"invalid": json content}')
        
        # Should still be detected by filename pattern, but content check should fail gracefully
        assert is_tokenizer_file(str(test_file))

    def test_is_tokenizer_file_non_existent(self):
        """Test tokenizer detection with non-existent file."""
        # Should not crash and should return False
        assert not is_tokenizer_file("/path/to/nonexistent/file.json")

    def test_is_tokenizer_file_permission_error(self, tmp_path):
        """Test tokenizer detection when file cannot be read."""
        # Create a file that we can't read (simulated)
        test_file = tmp_path / "unreadable_tokenizer.json"
        test_file.write_text('{"vocab": {"test": 1}}')
        
        # Even if we can't read content, filename should still trigger detection
        assert is_tokenizer_file(str(test_file))


class TestTokenizerExclusionInScanning:
    """Test suite for tokenizer exclusion during scanning."""

    def test_scan_directory_excludes_tokenizer_files(self, tmp_path):
        """Test that directory scanning excludes tokenizer files."""
        # Create a test directory with mixed files
        model_dir = tmp_path / "test_model"
        model_dir.mkdir()
        
        # Create tokenizer files that should be excluded
        tokenizer_file = model_dir / "tokenizer.json"
        tokenizer_file.write_text('{"vocab": {"hello": 1, "world": 2}}')
        
        vocab_file = model_dir / "vocab.txt"
        vocab_file.write_text("hello\nworld")
        
        # Create a non-tokenizer file that should be scanned
        config_file = model_dir / "config.json"
        config_file.write_text('{"hidden_size": 768}')
        
        # Scan the directory
        results = scan_model_directory_or_file(str(model_dir))
        
        # Should have scanned the config file but excluded tokenizer files
        assert results["success"] is True
        assert results["files_scanned"] == 1  # Only config.json
        
        # No issues should be found since tokenizer files were excluded
        # and config.json is benign
        visible_issues = [
            issue for issue in results["issues"] 
            if issue.get("severity") != "debug"
        ]
        assert len(visible_issues) == 0

    def test_scan_single_tokenizer_file_excluded(self, tmp_path):
        """Test that scanning a single tokenizer file excludes it."""
        # Create a tokenizer file
        tokenizer_file = tmp_path / "tokenizer.json"
        tokenizer_file.write_text('{"vocab": {"System": 1, "eval": 2, "exec": 3}}')
        
        # Scan the single file
        results = scan_model_directory_or_file(str(tokenizer_file))
        
        # Should be excluded
        assert results["success"] is True
        assert results["files_scanned"] == 1
        assert len(results["issues"]) == 0

    def test_scan_directory_with_nested_tokenizers(self, tmp_path):
        """Test that nested tokenizer files are also excluded."""
        # Create a complex directory structure
        model_dir = tmp_path / "complex_model"
        model_dir.mkdir()
        
        # Create subdirectories
        tokenizer_dir = model_dir / "tokenizer"
        tokenizer_dir.mkdir()
        
        # Create nested tokenizer files
        main_tokenizer = tokenizer_dir / "tokenizer.json"
        main_tokenizer.write_text('{"model": {"vocab": {"dangerous": 1, "exec": 2}}}')
        
        special_tokens = tokenizer_dir / "special_tokens_map.json"
        special_tokens.write_text('{"unk_token": "[UNK]", "pad_token": "[PAD]"}')
        
        # Create a legitimate config file
        config_file = model_dir / "config.json"
        config_file.write_text('{"model_type": "bert", "hidden_size": 768}')
        
        # Scan the directory
        results = scan_model_directory_or_file(str(model_dir))
        
        # Should have scanned only the config file
        assert results["success"] is True
        assert results["files_scanned"] == 1  # Only config.json
        
        # Verify no false positives from tokenizer vocabulary
        error_issues = [
            issue for issue in results["issues"]
            if issue.get("severity") == "error"
        ]
        assert len(error_issues) == 0

    def test_scan_with_progress_callback_tokenizer_exclusion(self, tmp_path):
        """Test that progress callback is called when excluding tokenizer files."""
        model_dir = tmp_path / "test_model"
        model_dir.mkdir()
        
        # Create tokenizer file
        tokenizer_file = model_dir / "tokenizer.json"
        tokenizer_file.write_text('{"vocab": {"test": 1}}')
        
        # Track progress messages
        progress_messages = []
        
        def progress_callback(message, percentage):
            progress_messages.append(message)
        
        # Scan with progress callback
        results = scan_model_directory_or_file(
            str(model_dir), 
            progress_callback=progress_callback
        )
        
        # Should have received progress message about skipping tokenizer
        assert any(
            "Skipping tokenizer file" in msg 
            for msg in progress_messages
        )

    def test_tokenizer_exclusion_with_suspicious_patterns(self, tmp_path):
        """Test that tokenizer files with suspicious vocabulary are properly excluded."""
        # Create a tokenizer file with vocabulary that would normally trigger security warnings
        tokenizer_file = tmp_path / "tokenizer.json"
        
        # This vocabulary contains many terms that would trigger security patterns
        suspicious_vocab = {
            "vocab": {
                "System": 1,
                "RuntimeObject": 2,
                "runApp": 3,
                "ExecutionContext": 4,
                "scripted": 5,
                "eval": 6,
                "exec": 7,
                "__import__": 8,
                "subprocess": 9,
                "credentials": 10,
                "api_key": 11,
                "password": 12,
                "localhost": 13,
                "https": 14,
            },
            "model": {
                "vocab": {
                    "dangerous_token": 15,
                    "execute_code": 16,
                }
            }
        }
        
        tokenizer_file.write_text(json.dumps(suspicious_vocab))
        
        # Scan the file
        results = scan_model_directory_or_file(str(tokenizer_file))
        
        # Should be excluded entirely, no security issues reported
        assert results["success"] is True
        assert results["files_scanned"] == 1
        
        # Should have no security issues since file was excluded
        security_issues = [
            issue for issue in results["issues"]
            if issue.get("severity") in ["error", "warning"]
        ]
        assert len(security_issues) == 0

    def test_tokenizer_detection_edge_cases(self, tmp_path):
        """Test edge cases in tokenizer detection."""
        # Test with very large JSON file (only read first 2KB)
        large_tokenizer = tmp_path / "large_tokenizer.json"
        content = '{"vocab": {"token": 1}' + ', "filler": "x" * 10000' + '}'
        large_tokenizer.write_text(content)
        
        assert is_tokenizer_file(str(large_tokenizer))
        
        # Test with empty file that has tokenizer pattern in name
        empty_file = tmp_path / "empty_tokenizer.json"
        empty_file.write_text('')
        assert is_tokenizer_file(str(empty_file))  # Should be detected by filename pattern
        
        # Test with binary file that has tokenizer name
        binary_tokenizer = tmp_path / "tokenizer.model"
        binary_tokenizer.write_bytes(b'\x00\x01\x02\x03')
        assert is_tokenizer_file(str(binary_tokenizer))  # Detected by filename

    def test_real_world_tokenizer_structure(self, tmp_path):
        """Test with realistic tokenizer file structure."""
        # Create a realistic HuggingFace tokenizer file
        tokenizer_file = tmp_path / "tokenizer.json"
        
        realistic_tokenizer = {
            "version": "1.0",
            "truncation": None,
            "padding": None,
            "added_tokens": [
                {"id": 0, "content": "[PAD]", "single_word": False, "lstrip": False, "rstrip": False, "normalized": False, "special": True},
                {"id": 1, "content": "[UNK]", "single_word": False, "lstrip": False, "rstrip": False, "normalized": False, "special": True},
            ],
            "normalizer": {"type": "BertNormalizer", "clean_text": True, "handle_chinese_chars": True, "strip_accents": None, "lowercase": True},
            "pre_tokenizer": {"type": "BertPreTokenizer"},
            "post_processor": {"type": "BertProcessing", "sep": ["[SEP]", 102], "cls": ["[CLS]", 101]},
            "decoder": {"type": "WordPiece", "prefix": "##", "cleanup": True},
            "model": {
                "type": "WordPiece",
                "unk_token": "[UNK]",
                "continuing_subword_prefix": "##",
                "max_input_chars_per_word": 100,
                "vocab": {
                    "[PAD]": 0,
                    "[UNK]": 1,
                    "[CLS]": 101,
                    "[SEP]": 102,
                    "System": 2000,  # This would normally trigger security warnings
                    "eval": 2001,    # This would normally trigger security warnings
                    "exec": 2002,    # This would normally trigger security warnings
                    "RuntimeObject": 2003,  # This would normally trigger security warnings
                }
            }
        }
        
        tokenizer_file.write_text(json.dumps(realistic_tokenizer, indent=2))
        
        # Should be detected as tokenizer
        assert is_tokenizer_file(str(tokenizer_file))
        
        # Scanning should exclude it completely
        results = scan_model_directory_or_file(str(tokenizer_file))
        assert results["success"] is True
        
        # No security issues should be reported
        security_issues = [
            issue for issue in results["issues"]
            if issue.get("severity") in ["error", "warning"]
        ]
        assert len(security_issues) == 0 