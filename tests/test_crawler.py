#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for utils/crawler.py — Crawler class."""

import unittest
from unittest.mock import MagicMock


class _MockResponse:
    def __init__(self, text='', status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class _MockRequester:
    def __init__(self, responses=None):
        self._responses = responses or {}

    def request(self, url, method, **kwargs):
        if url in self._responses:
            return self._responses[url]
        return None


class _MockEngine:
    def __init__(self, responses=None):
        self.config = {'verbose': False}
        self.requester = _MockRequester(responses)


class TestCrawlerInit(unittest.TestCase):
    """Crawler constructor."""

    def test_sets_engine(self):
        from utils.crawler import Crawler
        engine = _MockEngine()
        c = Crawler(engine)
        self.assertIs(c.engine, engine)

    def test_empty_visited(self):
        from utils.crawler import Crawler
        c = Crawler(_MockEngine())
        self.assertEqual(len(c.visited), 0)

    def test_empty_forms(self):
        from utils.crawler import Crawler
        c = Crawler(_MockEngine())
        self.assertEqual(c.forms, [])

    def test_resources_keys(self):
        from utils.crawler import Crawler
        c = Crawler(_MockEngine())
        for key in ('scripts', 'stylesheets', 'images', 'iframes', 'media', 'comments'):
            self.assertIn(key, c.resources)


class TestExtractParameters(unittest.TestCase):
    """Crawler._extract_parameters from URL query strings."""

    def test_single_param(self):
        from utils.crawler import Crawler
        c = Crawler(_MockEngine())
        c._extract_parameters('http://example.com/page?id=1')
        self.assertEqual(len(c.parameters), 1)
        self.assertEqual(c.parameters[0][2], 'id')
        self.assertEqual(c.parameters[0][3], '1')

    def test_multiple_params(self):
        from utils.crawler import Crawler
        c = Crawler(_MockEngine())
        c._extract_parameters('http://example.com/page?id=1&name=test')
        self.assertEqual(len(c.parameters), 2)

    def test_no_params(self):
        from utils.crawler import Crawler
        c = Crawler(_MockEngine())
        c._extract_parameters('http://example.com/page')
        self.assertEqual(len(c.parameters), 0)


class TestExtractForms(unittest.TestCase):
    """Crawler._extract_forms from BeautifulSoup parsed HTML."""

    def _make(self):
        from utils.crawler import Crawler
        return Crawler(_MockEngine())

    def test_simple_form(self):
        from bs4 import BeautifulSoup
        c = self._make()
        html = '<form action="/search" method="get"><input name="q" type="text"></form>'
        soup = BeautifulSoup(html, 'html.parser')
        c._extract_forms(soup, 'http://example.com')
        self.assertEqual(len(c.forms), 1)
        self.assertEqual(c.forms[0]['method'], 'get')
        self.assertEqual(len(c.forms[0]['inputs']), 1)
        self.assertEqual(c.forms[0]['inputs'][0]['name'], 'q')

    def test_post_form(self):
        from bs4 import BeautifulSoup
        c = self._make()
        html = '<form action="/login" method="POST"><input name="user"><input name="pass" type="password"></form>'
        soup = BeautifulSoup(html, 'html.parser')
        c._extract_forms(soup, 'http://example.com')
        self.assertEqual(c.forms[0]['method'], 'post')
        self.assertEqual(len(c.forms[0]['inputs']), 2)

    def test_form_adds_parameters(self):
        from bs4 import BeautifulSoup
        c = self._make()
        html = '<form action="/s"><input name="q"></form>'
        soup = BeautifulSoup(html, 'html.parser')
        c._extract_forms(soup, 'http://example.com')
        self.assertTrue(len(c.parameters) > 0)
        self.assertEqual(c.parameters[0][4], 'form')

    def test_no_forms(self):
        from bs4 import BeautifulSoup
        c = self._make()
        soup = BeautifulSoup('<div>Hello</div>', 'html.parser')
        c._extract_forms(soup, 'http://example.com')
        self.assertEqual(len(c.forms), 0)


class TestExtractResources(unittest.TestCase):
    """Crawler._extract_resources collects scripts, stylesheets, images, etc."""

    def _make(self):
        from utils.crawler import Crawler
        return Crawler(_MockEngine())

    def test_extract_script_src(self):
        from bs4 import BeautifulSoup
        c = self._make()
        html = '<script src="/js/app.js"></script>'
        soup = BeautifulSoup(html, 'html.parser')
        c._extract_resources(soup, 'http://example.com')
        self.assertEqual(len(c.resources['scripts']), 1)
        self.assertIn('http://example.com/js/app.js', c.resources['scripts'])

    def test_extract_stylesheet(self):
        from bs4 import BeautifulSoup
        c = self._make()
        html = '<link rel="stylesheet" href="/css/style.css">'
        soup = BeautifulSoup(html, 'html.parser')
        c._extract_resources(soup, 'http://example.com')
        self.assertEqual(len(c.resources['stylesheets']), 1)

    def test_extract_image(self):
        from bs4 import BeautifulSoup
        c = self._make()
        html = '<img src="/img/logo.png">'
        soup = BeautifulSoup(html, 'html.parser')
        c._extract_resources(soup, 'http://example.com')
        self.assertEqual(len(c.resources['images']), 1)

    def test_extract_iframe(self):
        from bs4 import BeautifulSoup
        c = self._make()
        html = '<iframe src="/embed/video"></iframe>'
        soup = BeautifulSoup(html, 'html.parser')
        c._extract_resources(soup, 'http://example.com')
        self.assertEqual(len(c.resources['iframes']), 1)


class TestExtractHiddenParams(unittest.TestCase):
    """Crawler._extract_hidden_params from hidden inputs and data attrs."""

    def _make(self):
        from utils.crawler import Crawler
        return Crawler(_MockEngine())

    def test_hidden_input(self):
        from bs4 import BeautifulSoup
        c = self._make()
        html = '<input type="hidden" name="csrf_token" value="abc123">'
        soup = BeautifulSoup(html, 'html.parser')
        c._extract_hidden_params(soup, 'http://example.com')
        self.assertTrue(any(p[2] == 'csrf_token' for p in c.parameters))

    def test_data_url_attribute(self):
        from bs4 import BeautifulSoup
        c = self._make()
        html = '<div data-url="/api/endpoint"></div>'
        soup = BeautifulSoup(html, 'html.parser')
        c._extract_hidden_params(soup, 'http://example.com')
        self.assertTrue(any(p[4] == 'data_attr' for p in c.parameters))

    def test_meta_with_url(self):
        from bs4 import BeautifulSoup
        c = self._make()
        html = '<meta content="http://example.com/redirect">'
        soup = BeautifulSoup(html, 'html.parser')
        c._extract_hidden_params(soup, 'http://example.com')
        self.assertTrue(any(p[4] == 'meta' for p in c.parameters))


class TestExtractComments(unittest.TestCase):
    """Crawler._extract_comments collects HTML comments."""

    def _make(self):
        from utils.crawler import Crawler
        return Crawler(_MockEngine())

    def test_single_comment(self):
        from bs4 import BeautifulSoup
        c = self._make()
        html = '<html><!-- TODO: remove debug endpoint --><body></body></html>'
        soup = BeautifulSoup(html, 'html.parser')
        c._extract_comments(soup, 'http://example.com')
        self.assertEqual(len(c.resources['comments']), 1)
        self.assertIn('debug', c.resources['comments'][0]['comment'])

    def test_no_comments(self):
        from bs4 import BeautifulSoup
        c = self._make()
        soup = BeautifulSoup('<html><body></body></html>', 'html.parser')
        c._extract_comments(soup, 'http://example.com')
        self.assertEqual(len(c.resources['comments']), 0)


class TestUpdateGraph(unittest.TestCase):
    """Crawler._update_graph tracks endpoint metadata."""

    def _make(self):
        from utils.crawler import Crawler
        return Crawler(_MockEngine())

    def test_graph_entry_created(self):
        from bs4 import BeautifulSoup
        c = self._make()
        resp = _MockResponse(text='', status_code=200)
        soup = BeautifulSoup('<html><body></body></html>', 'html.parser')
        c._update_graph('http://example.com/page', resp, soup)
        self.assertIn('/page', c.endpoint_graph)

    def test_graph_tracks_methods(self):
        from bs4 import BeautifulSoup
        c = self._make()
        resp = _MockResponse()
        html = '<form method="POST"><input name="data"></form>'
        soup = BeautifulSoup(html, 'html.parser')
        c._update_graph('http://example.com/api', resp, soup)
        entry = c.endpoint_graph['/api']
        self.assertIn('GET', entry['methods'])
        self.assertIn('POST', entry['methods'])

    def test_graph_detects_auth_endpoint(self):
        from bs4 import BeautifulSoup
        c = self._make()
        resp = _MockResponse()
        soup = BeautifulSoup('<html></html>', 'html.parser')
        c._update_graph('http://example.com/login', resp, soup)
        self.assertEqual(c.endpoint_graph['/login']['auth_state'], 'auth_endpoint')

    def test_graph_detects_401(self):
        from bs4 import BeautifulSoup
        c = self._make()
        resp = _MockResponse(status_code=401)
        soup = BeautifulSoup('<html></html>', 'html.parser')
        c._update_graph('http://example.com/admin', resp, soup)
        self.assertEqual(c.endpoint_graph['/admin']['auth_state'], 'requires_auth')

    def test_graph_tracks_related(self):
        from bs4 import BeautifulSoup
        c = self._make()
        resp = _MockResponse()
        html = '<a href="/other">Link</a>'
        soup = BeautifulSoup(html, 'html.parser')
        c._update_graph('http://example.com/page', resp, soup)
        self.assertIn('/other', c.endpoint_graph['/page']['related'])


class TestGetGraphSummary(unittest.TestCase):
    """Crawler.get_graph_summary produces readable text."""

    def test_empty_graph(self):
        from utils.crawler import Crawler
        c = Crawler(_MockEngine())
        self.assertEqual(c.get_graph_summary(), '')

    def test_non_empty_graph(self):
        from utils.crawler import Crawler
        from bs4 import BeautifulSoup
        c = Crawler(_MockEngine())
        resp = _MockResponse()
        soup = BeautifulSoup('<html></html>', 'html.parser')
        c._update_graph('http://example.com/', resp, soup)
        summary = c.get_graph_summary()
        self.assertIn('[GET]', summary)


if __name__ == '__main__':
    unittest.main()
