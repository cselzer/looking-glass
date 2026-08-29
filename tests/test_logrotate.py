import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from looking_glass.logrotate import append_line, copytruncate_if_needed, rotate_if_needed


class LogRotateTests(unittest.TestCase):
    def test_rename_rotate_keeps_all_when_keep_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "app.log")
            Path(path).write_text("old\n", encoding="utf-8")
            with patch("looking_glass.logrotate.settings", return_value=(4, -1)):
                self.assertTrue(rotate_if_needed(path))
                append_line(path, "new")
            self.assertTrue(Path(path + ".1").is_file())
            self.assertEqual(Path(path).read_text(encoding="utf-8"), "new\n")
            Path(path).write_text("again\n", encoding="utf-8")
            with patch("looking_glass.logrotate.settings", return_value=(4, -1)):
                self.assertTrue(rotate_if_needed(path))
            self.assertTrue(Path(path + ".1").is_file())
            self.assertTrue(Path(path + ".2").is_file())

    def test_copytruncate_keeps_inode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "held.log")
            with open(path, "a", encoding="utf-8") as held:
                held.write("0123456789\n")
                held.flush()
                inode = os.fstat(held.fileno()).st_ino
                with patch("looking_glass.logrotate.settings", return_value=(4, 2)):
                    self.assertTrue(copytruncate_if_needed(path))
                held.write("after\n")
                held.flush()
            self.assertEqual(os.stat(path).st_ino, inode)
            self.assertIn("after", Path(path).read_text(encoding="utf-8"))
            self.assertTrue(Path(path + ".1").is_file())
