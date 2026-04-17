#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Comparer Utility - Burp Suite Style Response Diff Tool"""

import difflib


class Comparer:
    """HTTP response comparison and diff utility."""

    # ------------------------------------------------------------------ #
    #  Public API                                                         #
    # ------------------------------------------------------------------ #

    def compare_responses(self, response1, response2):
        """Compare two HTTP responses and return a detailed diff report.

        Each response is a dict with keys: status_code, headers, body.
        Returns a dict with status, headers, body and similarity sections.
        """
        r1 = self._normalise_response(response1)
        r2 = self._normalise_response(response2)

        status_diff = self._compare_status(r1["status_code"], r2["status_code"])
        header_diff = self.compare_headers(r1["headers"], r2["headers"])
        body_diff = self.diff_text(r1["body"], r2["body"])
        body_similarity = self.similarity_ratio(r1["body"], r2["body"])

        return {
            "status": status_diff,
            "headers": header_diff,
            "body_diff": body_diff,
            "body_similarity": body_similarity,
        }

    # -- text diff ----------------------------------------------------- #

    def diff_text(self, text1, text2, context_lines=3):
        """Generate a unified diff between two text blocks."""
        lines1 = text1.splitlines(keepends=True)
        lines2 = text2.splitlines(keepends=True)
        return list(
            difflib.unified_diff(
                lines1,
                lines2,
                fromfile="response1",
                tofile="response2",
                n=context_lines,
            )
        )

    # -- binary diff --------------------------------------------------- #

    def diff_bytes(self, bytes1, bytes2):
        """Compare binary data and return a hex diff."""
        hex1 = self._hex_lines(bytes1)
        hex2 = self._hex_lines(bytes2)
        return list(
            difflib.unified_diff(
                hex1,
                hex2,
                fromfile="binary1",
                tofile="binary2",
                lineterm="",
            )
        )

    # -- similarity ---------------------------------------------------- #

    def similarity_ratio(self, text1, text2):
        """Return a similarity ratio (0.0–1.0) using SequenceMatcher."""
        return difflib.SequenceMatcher(None, text1, text2).ratio()

    # -- highlight ----------------------------------------------------- #

    def highlight_differences(self, text1, text2):
        """Return a list of (type, content) tuples.

        type is one of: 'equal', 'added', 'removed', 'changed'.
        """
        matcher = difflib.SequenceMatcher(None, text1.splitlines(), text2.splitlines())
        result = []
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                for line in text1.splitlines()[i1:i2]:
                    result.append(("equal", line))
            elif tag == "insert":
                for line in text2.splitlines()[j1:j2]:
                    result.append(("added", line))
            elif tag == "delete":
                for line in text1.splitlines()[i1:i2]:
                    result.append(("removed", line))
            elif tag == "replace":
                for line in text1.splitlines()[i1:i2]:
                    result.append(("changed", line))
                for line in text2.splitlines()[j1:j2]:
                    result.append(("changed", line))
        return result

    # -- header comparison --------------------------------------------- #

    def compare_headers(self, headers1, headers2):
        """Compare two sets of HTTP headers.

        Returns a dict with 'added', 'removed' and 'changed' keys.
        """
        h1 = {k.lower(): v for k, v in headers1.items()}
        h2 = {k.lower(): v for k, v in headers2.items()}

        keys1 = set(h1)
        keys2 = set(h2)

        added = {k: h2[k] for k in sorted(keys2 - keys1)}
        removed = {k: h1[k] for k in sorted(keys1 - keys2)}
        changed = {}
        for k in sorted(keys1 & keys2):
            if h1[k] != h2[k]:
                changed[k] = {"from": h1[k], "to": h2[k]}

        return {"added": added, "removed": removed, "changed": changed}

    # -- word diff ----------------------------------------------------- #

    def word_diff(self, text1, text2):
        """Word-level diff instead of line-level.

        Returns a list of (tag, content) tuples where tag is
        'equal', 'insert', or 'delete'.
        """
        words1 = text1.split()
        words2 = text2.split()
        matcher = difflib.SequenceMatcher(None, words1, words2)
        result = []
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                result.append(("equal", " ".join(words1[i1:i2])))
            elif tag == "insert":
                result.append(("insert", " ".join(words2[j1:j2])))
            elif tag == "delete":
                result.append(("delete", " ".join(words1[i1:i2])))
            elif tag == "replace":
                result.append(("delete", " ".join(words1[i1:i2])))
                result.append(("insert", " ".join(words2[j1:j2])))
        return result

    # -- summary ------------------------------------------------------- #

    def summary(self, response1, response2):
        """Return a brief human-readable summary of differences."""
        r1 = self._normalise_response(response1)
        r2 = self._normalise_response(response2)

        parts = []

        # Status code
        if r1["status_code"] != r2["status_code"]:
            parts.append(f"Status changed: {r1['status_code']} -> {r2['status_code']}")
        else:
            parts.append(f"Status: {r1['status_code']} (unchanged)")

        # Content length
        len1 = len(r1["body"])
        len2 = len(r2["body"])
        diff = len2 - len1
        if diff != 0:
            sign = "+" if diff > 0 else ""
            parts.append(f"Content length diff: {sign}{diff} chars")
        else:
            parts.append("Content length: unchanged")

        # Header changes
        hdiff = self.compare_headers(r1["headers"], r2["headers"])
        h_changes = len(hdiff["added"]) + len(hdiff["removed"]) + len(hdiff["changed"])
        if h_changes:
            parts.append(
                f"Header changes: {len(hdiff['added'])} added, "
                f"{len(hdiff['removed'])} removed, "
                f"{len(hdiff['changed'])} modified"
            )
        else:
            parts.append("Headers: unchanged")

        # Body similarity
        sim = self.similarity_ratio(r1["body"], r2["body"])
        parts.append(f"Body similarity: {sim:.1%}")

        return "; ".join(parts)

    # ------------------------------------------------------------------ #
    #  Private helpers                                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _normalise_response(resp):
        """Ensure the response dict has the expected keys with defaults."""
        return {
            "status_code": resp.get("status_code", 0),
            "headers": resp.get("headers", {}),
            "body": resp.get("body", ""),
        }

    @staticmethod
    def _compare_status(code1, code2):
        """Return a status comparison dict."""
        return {
            "response1": code1,
            "response2": code2,
            "changed": code1 != code2,
        }

    @staticmethod
    def _hex_lines(data, width=16):
        """Convert bytes to a list of hex-dump lines."""
        lines = []
        for offset in range(0, len(data), width):
            chunk = data[offset : offset + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")
        return lines
