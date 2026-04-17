#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the risk-based prioritization engine (core/prioritizer.py)."""

import unittest

from core.prioritizer import EndpointPrioritizer, SKIP_THRESHOLD

# ---------------------------------------------------------------------------
# Helpers / mocks
# ---------------------------------------------------------------------------


class _MockEngine:
    """Minimal mock that satisfies EndpointPrioritizer(engine)."""

    def __init__(self):
        self.config = {"verbose": False}


def _make_enriched_param(
    url="http://example.com/page", method="GET", param="id", value="1", source="crawl", predictions=None
):
    """Return a minimal enriched-parameter dict."""
    return {
        "url": url,
        "method": method,
        "param": param,
        "value": value,
        "source": source,
        "predictions": predictions or {},
    }


# ---------------------------------------------------------------------------
# score_endpoint tests
# ---------------------------------------------------------------------------


class TestScoreEndpoint(unittest.TestCase):

    def setUp(self):
        self.pri = EndpointPrioritizer(_MockEngine())

    # 1. Plain URL base score
    def test_plain_url_base_score(self):
        """A generic URL with no pattern matches should return the 0.5 base."""
        score = self.pri.score_endpoint("http://example.com/page")
        self.assertAlmostEqual(score, 0.5)

    # 2. Auth URL → high score ~0.9
    def test_auth_url_high_score(self):
        score = self.pri.score_endpoint("http://x.com/login")
        self.assertAlmostEqual(score, 0.9)

    # 3. Admin URL → ~0.85
    def test_admin_url_high_score(self):
        score = self.pri.score_endpoint("http://x.com/admin/dashboard")
        self.assertGreaterEqual(score, 0.85)

    # 4. API endpoint boost
    def test_api_endpoint_boost(self):
        score = self.pri.score_endpoint("http://x.com/api/users")
        self.assertGreaterEqual(score, 0.8)

    # 5. Upload endpoint boost
    def test_upload_endpoint_boost(self):
        score = self.pri.score_endpoint("http://x.com/upload/file")
        self.assertGreaterEqual(score, 0.8)

    # 6. Payment endpoint boost
    def test_payment_endpoint_boost(self):
        score = self.pri.score_endpoint("http://x.com/checkout/billing")
        self.assertGreaterEqual(score, 0.75)

    # 7. Static asset → low / negative penalty
    def test_static_asset_penalty(self):
        score = self.pri.score_endpoint("http://x.com/style.css")
        self.assertLess(score, 0.5)

    # 8. Informational page penalty
    def test_informational_page_penalty(self):
        score = self.pri.score_endpoint("http://x.com/about")
        self.assertLess(score, 0.5)

    # 9. POST method adds +0.1
    def test_post_method_boost(self):
        get_score = self.pri.score_endpoint("http://example.com/page", method="GET")
        post_score = self.pri.score_endpoint("http://example.com/page", method="POST")
        self.assertAlmostEqual(post_score - get_score, 0.1)

    # 10. Source = 'form' boost
    def test_source_form_boost(self):
        base = self.pri.score_endpoint("http://example.com/page", source="")
        boosted = self.pri.score_endpoint("http://example.com/page", source="form")
        self.assertAlmostEqual(boosted - base, 0.1)

    # 10b. Source = 'api' boost
    def test_source_api_boost(self):
        base = self.pri.score_endpoint("http://example.com/page", source="")
        boosted = self.pri.score_endpoint("http://example.com/page", source="api")
        self.assertAlmostEqual(boosted - base, 0.15)

    # 11. Auth param boosts to >= 0.85
    def test_auth_param_boost(self):
        score = self.pri.score_endpoint("http://example.com/page", param="token")
        self.assertGreaterEqual(score, 0.85)

    def test_auth_param_jwt(self):
        score = self.pri.score_endpoint("http://example.com/page", param="jwt")
        self.assertGreaterEqual(score, 0.85)

    # 12. Upload param boosts to >= 0.8
    def test_upload_param_boost(self):
        score = self.pri.score_endpoint("http://example.com/page", param="file")
        self.assertGreaterEqual(score, 0.8)

    # 13. Score clamped between 0.0 and 1.0
    def test_score_clamped_upper(self):
        """Stacking many boosts should not exceed 1.0."""
        score = self.pri.score_endpoint(
            "http://x.com/login",
            method="POST",
            param="token",
            source="api",
        )
        self.assertLessEqual(score, 1.0)

    def test_score_clamped_lower(self):
        """Heavy penalties should not go below 0.0."""
        score = self.pri.score_endpoint("http://x.com/static/assets/fonts/icon.woff")
        self.assertGreaterEqual(score, 0.0)


# ---------------------------------------------------------------------------
# prioritize_urls tests
# ---------------------------------------------------------------------------


class TestPrioritizeUrls(unittest.TestCase):

    def setUp(self):
        self.pri = EndpointPrioritizer(_MockEngine())

    # 14. Returns sorted list of (url, score) tuples
    def test_returns_sorted_tuples(self):
        urls = [
            "http://x.com/about",
            "http://x.com/login",
            "http://x.com/page",
        ]
        result = self.pri.prioritize_urls(urls)
        self.assertIsInstance(result, list)
        self.assertTrue(all(isinstance(t, tuple) and len(t) == 2 for t in result))
        scores = [s for _, s in result]
        self.assertEqual(scores, sorted(scores, reverse=True))

    # 15. Filters URLs below SKIP_THRESHOLD
    def test_filters_below_skip_threshold(self):
        urls = [
            "http://x.com/static/assets/fonts/icon.woff",
            "http://x.com/login",
        ]
        result = self.pri.prioritize_urls(urls)
        for url, score in result:
            self.assertGreaterEqual(score, SKIP_THRESHOLD)


# ---------------------------------------------------------------------------
# prioritize_parameters tests
# ---------------------------------------------------------------------------


class TestPrioritizeParameters(unittest.TestCase):

    def setUp(self):
        self.pri = EndpointPrioritizer(_MockEngine())

    # 16. Combines base score with prediction weight
    def test_combines_base_and_prediction(self):
        ep = _make_enriched_param(
            url="http://example.com/page",
            predictions={"sqli": 0.9},
        )
        result = self.pri.prioritize_parameters([ep])
        self.assertEqual(len(result), 1)
        # priority = 0.6 * base(0.5) + 0.4 * max_prediction(0.9) = 0.66
        self.assertAlmostEqual(result[0]["priority"], 0.66, places=2)

    # 17. Sorted HIGH → LOW
    def test_sorted_high_to_low(self):
        params = [
            _make_enriched_param(url="http://x.com/page", predictions={"sqli": 0.1}),
            _make_enriched_param(url="http://x.com/login", predictions={"sqli": 0.9}),
            _make_enriched_param(url="http://x.com/api/data", predictions={"sqli": 0.5}),
        ]
        result = self.pri.prioritize_parameters(params)
        priorities = [r["priority"] for r in result]
        self.assertEqual(priorities, sorted(priorities, reverse=True))

    # 18. Removes items below SKIP_THRESHOLD
    def test_removes_below_skip_threshold(self):
        params = [
            _make_enriched_param(
                url="http://x.com/static/assets/fonts/icon.woff",
                predictions={},
            ),
            _make_enriched_param(url="http://x.com/login", predictions={"sqli": 0.8}),
        ]
        result = self.pri.prioritize_parameters(params)
        for ep in result:
            self.assertGreaterEqual(ep["priority"], SKIP_THRESHOLD)

    def test_priority_key_added(self):
        """Each returned dict should have a 'priority' key."""
        ep = _make_enriched_param(predictions={"xss": 0.5})
        result = self.pri.prioritize_parameters([ep])
        self.assertIn("priority", result[0])

    def test_empty_predictions_uses_zero(self):
        """Empty predictions dict → max_prediction = 0."""
        ep = _make_enriched_param(predictions={})
        result = self.pri.prioritize_parameters([ep])
        # priority = 0.6 * 0.5 + 0.4 * 0 = 0.3
        self.assertAlmostEqual(result[0]["priority"], 0.3, places=2)

    def test_empty_input_returns_empty(self):
        self.assertEqual(self.pri.prioritize_parameters([]), [])


if __name__ == "__main__":
    unittest.main()
