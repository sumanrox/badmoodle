"""Unit tests for badmoodle - version checking and vulnerability matching."""

import os
import sys
import unittest

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.update import parse_versions
from lib.version import check_in_range


class TestVersionChecking(unittest.TestCase):
    """Test version range checking and parsing."""

    def test_check_in_range_basic(self):
        """Test basic version range checking."""
        # Version 3.9.5 should be in range 3.9.0 to 3.9.10
        self.assertTrue(check_in_range('3.9.5', {'from': '3.9.0', 'to': '3.9.10'}))

        # Version 3.9.5 should NOT be in range 3.10.0 to 3.11.0
        self.assertFalse(check_in_range('3.9.5', {'from': '3.10.0', 'to': '3.11.0'}))

        # Version exactly at boundary
        self.assertTrue(check_in_range('3.9.0', {'from': '3.9.0', 'to': '3.9.10'}))
        self.assertTrue(check_in_range('3.9.10', {'from': '3.9.0', 'to': '3.9.10'}))

    def test_check_in_range_edge_cases(self):
        """Test edge cases in version checking."""
        # Two-digit minor/patch versions
        self.assertTrue(check_in_range('3.11.4', {'from': '3.11.0', 'to': '3.11.10'}))

        # Version with 'x' replaced
        self.assertTrue(check_in_range('3.9.5', {'from': '3.9.0', 'to': '3.9.99'}))


class TestVersionParsing(unittest.TestCase):
    """Test version string parsing from Moodle advisories."""

    def test_parse_versions_simple_range(self):
        """Test parsing simple version ranges."""
        result = parse_versions('3.9 to 3.9.10')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['from'], '3.9')
        self.assertEqual(result[0]['to'], '3.9.10')

    def test_parse_versions_multiple_ranges(self):
        """Test parsing multiple version ranges."""
        result = parse_versions('3.11 to 3.11.4, 3.10 to 3.10.8')
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['from'], '3.11')
        self.assertEqual(result[0]['to'], '3.11.4')
        self.assertEqual(result[1]['from'], '3.10')
        self.assertEqual(result[1]['to'], '3.10.8')

    def test_parse_versions_single_version(self):
        """Test parsing single version."""
        result = parse_versions('3.9')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['from'], '3.9')
        self.assertEqual(result[0]['to'], '3.9')  # Single version gets same from/to


if __name__ == '__main__':
    unittest.main()
