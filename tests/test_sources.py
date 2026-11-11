import json
import unittest
from pathlib import Path
from app.hook import decode_body
class DomainTests(unittest.TestCase):
    def test_identity(self): self.assertEqual(decode_body(b'{"event_id":"x"}')["event_id"],"x")
    def test_invalid_json(self):
        with self.assertRaises(ValueError): decode_body(b"[")
    def test_missing_id(self):
        with self.assertRaises(ValueError): decode_body(b'{"value":1}')

class FixtureTests(unittest.TestCase):
    def test_fixture_directory(self): self.assertTrue(Path("fixtures").is_dir())
