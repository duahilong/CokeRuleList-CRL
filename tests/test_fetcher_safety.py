import unittest
from unittest.mock import Mock, patch

from app.fetcher import fetch_url, validate_response_content


class FetcherSafetyTests(unittest.TestCase):
    def _response(self, text, content_type="text/plain"):
        response = Mock()
        response.status_code = 200
        response.text = text
        response.headers = {"Content-Type": content_type}
        return response

    def test_empty_and_whitespace_responses_are_rejected(self):
        self.assertIsNotNone(validate_response_content(""))
        self.assertIsNotNone(validate_response_content(" \n\t"))

    def test_html_error_page_is_rejected(self):
        self.assertIsNotNone(validate_response_content("<!DOCTYPE html><html></html>"))
        self.assertIsNotNone(validate_response_content("plain", "text/html; charset=utf-8"))

    @patch("app.fetcher.requests.get")
    def test_http_200_html_becomes_failed_fetch(self, mock_get):
        mock_get.return_value = self._response("<html>rate limited</html>", "text/html")
        with patch("app.fetcher.time.sleep"):
            result = fetch_url("https://example.com/rules.list", retries=1)
        self.assertFalse(result.success)
        self.assertIn("HTML", result.error)

    @patch("app.fetcher.requests.get")
    def test_valid_response_is_accepted(self, mock_get):
        mock_get.return_value = self._response("DOMAIN-SUFFIX,example.com")
        result = fetch_url("https://example.com/rules.list", retries=0)
        self.assertTrue(result.success)
        self.assertEqual("DOMAIN-SUFFIX,example.com", result.content)


if __name__ == "__main__":
    unittest.main()
