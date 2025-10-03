# tests/test_feedback.py
import unittest
from pathlib import Path
import sys

# Add project root to sys.path so Python can find gui.py
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.gui import get_password_feedback, format_feedback, split_estimates, secs_to_human

class TestFeedbackFunctions(unittest.TestCase):

    def test_empty_password(self):
        hints = get_password_feedback("")
        self.assertIn("Password is empty", hints[0])

    def test_short_password(self):
        pw = "abc123"
        hints = get_password_feedback(pw)
        # Length check
        self.assertTrue(any("Very short" in h for h in hints))
        # Contains digits
        self.assertTrue(any("Contains digits" in h for h in hints))
        # Mixed case check
        self.assertTrue(any("No uppercase letters" in h for h in hints))
        # Symbol check
        self.assertTrue(any("No symbols" in h for h in hints))

    def test_long_passphrase(self):
        pw = "forestAppleSolar19!"
        hints = get_password_feedback(pw)
        self.assertTrue(any("Length: 19 characters" in h for h in hints))
        self.assertTrue(any("Mixed case" in h for h in hints))
        self.assertTrue(any("Contains digits" in h for h in hints))
        self.assertTrue(any("Contains symbol(s)" in h for h in hints))

    def test_format_feedback_actions(self):
        hints = ["Short — consider 12+ characters for better strength."]
        fb_text = format_feedback({}, hints)
        self.assertIn("Actionable steps", fb_text)
        self.assertIn("Increase password length", fb_text)
        self.assertIn("Consider using a passphrase", fb_text)
        self.assertIn("Use multi-factor authentication", fb_text)

    def test_split_estimates(self):
        estimates = {
            "Per-account throttled (10/hr)": {"seconds": 3600},
            "Offline": {"seconds": 60}
        }
        online, offline = split_estimates(estimates)
        self.assertIn("Per-account throttled", online)
        self.assertIn("Offline", offline)

    def test_secs_to_human(self):
        self.assertEqual(secs_to_human(0.5), "0.500 seconds")
        self.assertEqual(secs_to_human(60), "1.00 minutes")
        self.assertEqual(secs_to_human(3600*25), "1.04 days")  # 25 hours

if __name__ == "__main__":
    unittest.main()
