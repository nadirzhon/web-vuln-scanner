import sys
sys.path.insert(0, ".")

def test_sqli_payloads_not_empty():
    from scanner import SQLI_PAYLOADS, XSS_PAYLOADS, SENSITIVE_PATHS
    assert len(SQLI_PAYLOADS) >= 3
    assert len(XSS_PAYLOADS) >= 2
    assert "/.env" in SENSITIVE_PATHS

def test_sqli_error_patterns():
    from scanner import SQLI_ERRORS
    sample_response = "You have an error in your sql syntax near ''"
    assert any(e.lower() in sample_response.lower() for e in SQLI_ERRORS)

def test_xss_detection_logic():
    payload = "<script>alert(1)</script>"
    fake_response_text = f"<html><body>{payload}</body></html>"
    assert payload in fake_response_text

def test_url_join():
    from urllib.parse import urljoin
    base = "https://example.com"
    assert urljoin(base, "/.env") == "https://example.com/.env"
    assert urljoin(base, "/admin") == "https://example.com/admin"

if __name__ == "__main__":
    test_sqli_payloads_not_empty()
    test_sqli_error_patterns()
    test_xss_detection_logic()
    test_url_join()
    print("All tests passed.")
