"""Tests for file iterator utility."""



from modelaudit.utils.helpers.file_iterator import iterate_files_streaming


class TestIterateFilesStreaming:
    """Tests for iterate_files_streaming function."""

    def test_single_file(self, tmp_path):
        """Test iteration with a single file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        results = list(iterate_files_streaming(test_file))

        assert len(results) == 1
        assert results[0][0] == test_file
        assert results[0][1] is True  # is_last

    def test_directory_with_files(self, tmp_path):
        """Test iteration with a directory containing files."""
        # Create test files
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.txt").write_text("content2")
        (tmp_path / "file3.txt").write_text("content3")

        results = list(iterate_files_streaming(tmp_path))

        assert len(results) == 3
        # Last file should have is_last=True
        assert sum(1 for _, is_last in results if is_last) == 1
        # Only the last item should have is_last=True
        assert results[-1][1] is True

    def test_directory_with_pattern(self, tmp_path):
        """Test iteration with a specific pattern."""
        # Create test files
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.py").write_text("content2")
        (tmp_path / "file3.txt").write_text("content3")

        # Only match .txt files
        results = list(iterate_files_streaming(tmp_path, pattern="*.txt"))

        assert len(results) == 2
        for path, _ in results:
            assert path.suffix == ".txt"

    def test_empty_directory(self, tmp_path):
        """Test iteration with an empty directory."""
        results = list(iterate_files_streaming(tmp_path))

        assert len(results) == 0

    def test_nonexistent_path(self, tmp_path):
        """Test iteration with a nonexistent path."""
        nonexistent = tmp_path / "nonexistent"

        results = list(iterate_files_streaming(nonexistent))

        assert len(results) == 0

    def test_nested_directories(self, tmp_path):
        """Test iteration with nested directories."""
        # Create nested structure
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (tmp_path / "root.txt").write_text("root")
        (subdir / "nested.txt").write_text("nested")

        results = list(iterate_files_streaming(tmp_path))

        assert len(results) == 2
        paths = [str(p) for p, _ in results]
        assert any("root.txt" in p for p in paths)
        assert any("nested.txt" in p for p in paths)

    def test_string_path(self, tmp_path):
        """Test iteration with a string path."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Pass as string instead of Path
        results = list(iterate_files_streaming(str(test_file)))

        assert len(results) == 1
        assert results[0][1] is True

    def test_is_last_flags_correct(self, tmp_path):
        """Test that is_last flags are correct."""
        # Create multiple files
        for i in range(5):
            (tmp_path / f"file{i}.txt").write_text(f"content{i}")

        results = list(iterate_files_streaming(tmp_path))

        assert len(results) == 5
        # First 4 should have is_last=False
        for _, is_last in results[:-1]:
            assert is_last is False
        # Last should have is_last=True
        assert results[-1][1] is True

    def test_subdirectory_pattern(self, tmp_path):
        """Test pattern matching in subdirectories."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "data.pkl").write_text("data")
        (tmp_path / "model.pkl").write_text("model")

        # Match pkl files recursively
        results = list(iterate_files_streaming(tmp_path, pattern="**/*.pkl"))

        assert len(results) == 2

    def test_no_matching_files(self, tmp_path):
        """Test when pattern matches no files."""
        (tmp_path / "file.txt").write_text("content")

        results = list(iterate_files_streaming(tmp_path, pattern="*.pkl"))

        assert len(results) == 0

    def test_generator_behavior(self, tmp_path):
        """Test that function returns a generator."""
        (tmp_path / "file.txt").write_text("content")

        result = iterate_files_streaming(tmp_path)

        # Should be an iterator/generator
        assert hasattr(result, "__iter__")
        assert hasattr(result, "__next__")
