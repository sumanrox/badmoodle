"""Tests for lib.update module."""
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from lib.update import parse_cves, parse_versions


def test_parse_versions_simple_range():
    """Test parsing simple version range."""
    result = parse_versions('3.9 to 3.9.5')
    assert len(result) == 1
    assert result[0]['from'] == '3.9'
    assert result[0]['to'] == '3.9.5'


def test_parse_versions_with_x_placeholders():
    """Test parsing versions with x placeholders."""
    result = parse_versions('3.9.x to 3.10.x')
    assert len(result) == 1
    assert result[0]['from'] == '3.9.0'
    assert result[0]['to'] == '3.10.99'


def test_parse_versions_multiple_ranges():
    """Test parsing multiple version ranges."""
    result = parse_versions('3.9 to 3.9.5 and 3.10 to 3.10.3')
    assert len(result) == 2
    assert result[0]['from'] == '3.9'
    assert result[0]['to'] == '3.9.5'
    assert result[1]['from'] == '3.10'
    assert result[1]['to'] == '3.10.3'


def test_parse_versions_all():
    """Test parsing 'all' versions."""
    result = parse_versions('all')
    assert len(result) == 1
    assert result[0]['from'] == '0.0.0'
    assert result[0]['to'] == '1.10.0'


def test_parse_versions_less_than():
    """Test parsing less-than operator."""
    result = parse_versions('< 3.9.5')
    assert len(result) == 1
    assert result[0]['from'] == '0.0.0'
    assert result[0]['to'] == '3.9.5'


def test_parse_versions_less_than_or_equal():
    """Test parsing less-than-or-equal operator."""
    result = parse_versions('<= 3.9.5')
    assert len(result) == 1
    assert result[0]['from'] == '0.0.0'
    assert result[0]['to'] == '3.9.5'


def test_parse_cves_with_valid_cve():
    """Test parsing CVEs from table rows."""
    # This is a simplified mock - in real scenario we'd need BeautifulSoup objects
    # For now, just test that the function exists and handles edge cases
    from bs4 import BeautifulSoup

    html = '''<table>
        <tr><td>CVE Identifier</td><td>CVE-2021-12345 CVE-2021-67890</td></tr>
    </table>'''
    soup = BeautifulSoup(html, 'html.parser')
    trs = soup.find_all('tr')

    result = parse_cves(trs)
    assert 'CVE-2021-12345' in result
    assert 'CVE-2021-67890' in result


def test_parse_cves_no_cve():
    """Test parsing when no CVE is present."""
    from bs4 import BeautifulSoup

    html = '''<table>
        <tr><td>Something</td><td>No CVE here</td></tr>
    </table>'''
    soup = BeautifulSoup(html, 'html.parser')
    trs = soup.find_all('tr')

    result = parse_cves(trs)
    assert result == ['N/A']
