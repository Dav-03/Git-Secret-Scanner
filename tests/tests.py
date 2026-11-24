from secretscan.diffParser import parse_diff
from secretscan.model import AddedLine


def _parse(text: str, commit: str = "") -> list[AddedLine]:
    return list(parse_diff(text.splitlines(keepends=True), default_commit=commit))


def test_single_commit_added_lines():
    diff = """COMMIT:abc123
diff --git a/config.py b/config.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/config.py
@@ -0,0 +1,2 @@
+API_KEY = "x"
+DEBUG = True
"""
    assert _parse(diff) == [
        AddedLine("abc123", "config.py", 1, 'API_KEY = "x"'),
        AddedLine("abc123", "config.py", 2, "DEBUG = True"),
    ]


def test_removed_lines_ignored_and_line_numbers_follow_hunk():
    diff = """COMMIT:abc
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -3 +3 @@
-old
+new
@@ -10,0 +11,2 @@
+x
+y
"""
    assert [(a.line_no, a.text) for a in _parse(diff)] == [(3, "new"), (11, "x"), (12, "y")]


def test_added_line_that_looks_like_header():
    diff = """COMMIT:abc
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -0,0 +1,2 @@
+++ not a header
+--- also not a header
"""
    assert [a.text for a in _parse(diff)] == ["++ not a header", "--- also not a header"]


def test_deleted_file_yields_nothing():
    diff = """COMMIT:abc
diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -1 +0,0 @@
-secret
"""
    assert _parse(diff) == []


def test_binary_file_skipped():
    diff = """COMMIT:abc
diff --git a/img.png b/img.png
new file mode 100644
Binary files /dev/null and b/img.png differ
diff --git a/b.txt b/b.txt
--- /dev/null
+++ b/b.txt
@@ -0,0 +1 @@
+hello
"""
    assert _parse(diff) == [AddedLine("abc", "b.txt", 1, "hello")]


def test_multiple_commits_and_files():
    diff = """COMMIT:c2
diff --git a/a b/a
--- a/a
+++ b/a
@@ -1 +1 @@
-1
+2
diff --git a/b b/b
--- /dev/null
+++ b/b
@@ -0,0 +1 @@
+b
COMMIT:c1
diff --git a/a b/a
--- /dev/null
+++ b/a
@@ -0,0 +1 @@
+1
"""
    assert [(a.commit, a.path, a.text) for a in _parse(diff)] == [
        ("c2", "a", "2"),
        ("c2", "b", "b"),
        ("c1", "a", "1"),
    ]


def test_no_newline_marker_and_crlf():
    diff = (
        "COMMIT:abc\r\ndiff --git a/w b/w\r\n--- /dev/null\r\n+++ b/w\r\n"
        "@@ -0,0 +1 @@\r\n+last\r\n\\ No newline at end of file\r\n"
    )
    assert _parse(diff) == [AddedLine("abc", "w", 1, "last")]


def test_quoted_path_with_space():
    diff = """COMMIT:abc
diff --git "a/my file.txt" "b/my file.txt"
--- /dev/null
+++ "b/my\\tfile.txt"
@@ -0,0 +1 @@
+hi
"""
    assert _parse(diff)[0].path == "my\tfile.txt"