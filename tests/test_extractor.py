import unittest
from src.context.extractor import redact_secrets, detect_enclosing_function


class TestExtractor(unittest.TestCase):
    def test_redact_secrets(self):
        raw_code = "const API_KEY = 'secret12345'; const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature';"
        redacted = redact_secrets(raw_code)
        self.assertNotIn("secret12345", redacted)
        self.assertIn("REDACTED", redacted)
        self.assertIn("[REDACTED_JWT_TOKEN]", redacted)

    def test_detect_enclosing_function(self):
        code_lines = [
            "const express = require('express');",
            "async function loginUser(req, res) {",
            "    const password = req.body.password;",
            "    const token = jwt.sign(user, 'dev_secret');",
            "    return res.json({ token });",
            "}"
        ]
        func_name = detect_enclosing_function(code_lines, 3)
        self.assertEqual(func_name, "loginUser")


if __name__ == "__main__":
    unittest.main()
