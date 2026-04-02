#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the Shell Manager module (modules/shell/manager.py)."""

import unittest
from unittest.mock import MagicMock, patch, mock_open
from datetime import datetime, timezone


# ===========================================================================
# ShellManager – Initialization
# ===========================================================================

class TestShellManagerInit(unittest.TestCase):

    @patch('modules.shell.manager.Database')
    def test_init_creates_database(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        mgr = ShellManager()
        mock_db_cls.assert_called_once()
        self.assertIs(mgr.db, mock_db_cls.return_value)

    @patch('modules.shell.manager.Database')
    def test_init_empty_shells_dict(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        mgr = ShellManager()
        self.assertEqual(mgr.shells, {})


# ===========================================================================
# ShellManager – list_shells()
# ===========================================================================

class TestShellManagerListShells(unittest.TestCase):

    @patch('modules.shell.manager.Database')
    def test_list_shells_no_shells(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        mock_db_cls.return_value.get_shells.return_value = []
        mgr = ShellManager()
        mgr.list_shells()
        self.assertEqual(mgr.shells, {})

    @patch('modules.shell.manager.Database')
    def test_list_shells_populates_dict(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        shells_data = [
            {
                'shell_id': 'abc123',
                'url': 'http://target.com/shell.php',
                'shell_type': 'php',
                'created_at': datetime(2024, 1, 1, tzinfo=timezone.utc),
            },
        ]
        mock_db_cls.return_value.get_shells.return_value = shells_data
        mgr = ShellManager()
        mgr.list_shells()
        self.assertIn('abc123', mgr.shells)
        self.assertEqual(mgr.shells['abc123']['url'], 'http://target.com/shell.php')

    @patch('modules.shell.manager.Database')
    def test_list_shells_multiple(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        shells_data = [
            {
                'shell_id': 'shell1',
                'url': 'http://a.com/s.php',
                'shell_type': 'php',
                'created_at': datetime(2024, 1, 1, tzinfo=timezone.utc),
            },
            {
                'shell_id': 'shell2',
                'url': 'http://b.com/s.asp',
                'shell_type': 'asp',
                'created_at': datetime(2024, 2, 1, tzinfo=timezone.utc),
            },
        ]
        mock_db_cls.return_value.get_shells.return_value = shells_data
        mgr = ShellManager()
        mgr.list_shells()
        self.assertEqual(len(mgr.shells), 2)

    @patch('modules.shell.manager.Database')
    def test_list_shells_truncates_long_url(self, mock_db_cls):
        """Long URLs are truncated in the display; shells dict keeps original."""
        from modules.shell.manager import ShellManager
        long_url = 'http://target.com/' + 'a' * 100
        shells_data = [
            {
                'shell_id': 'longurl-shell',
                'url': long_url,
                'shell_type': 'php',
                'created_at': datetime(2024, 6, 1, tzinfo=timezone.utc),
            },
        ]
        mock_db_cls.return_value.get_shells.return_value = shells_data
        mgr = ShellManager()
        mgr.list_shells()
        self.assertEqual(mgr.shells['longurl-shell']['url'], long_url)


# ===========================================================================
# ShellManager – execute_command()
# ===========================================================================

class TestShellManagerExecuteCommand(unittest.TestCase):

    @patch('modules.shell.manager.Database')
    def test_execute_command_builds_url_with_query(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        shell = {
            'shell_id': 's1',
            'url': 'http://target.com/shell.php',
            'password': 'cmd',
        }
        mock_db_cls.return_value.get_shells.return_value = [shell]
        mgr = ShellManager()

        with patch('requests.get') as mock_get:
            mock_resp = MagicMock()
            mock_resp.text = 'uid=0(root)'
            mock_get.return_value = mock_resp

            result = mgr.execute_command('s1', 'whoami', shell)
            self.assertEqual(result, 'uid=0(root)')
            called_url = mock_get.call_args[0][0]
            self.assertIn('cmd=whoami', called_url)

    @patch('modules.shell.manager.Database')
    def test_execute_command_appends_to_existing_query(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        shell = {
            'shell_id': 's2',
            'url': 'http://target.com/shell.php?token=abc',
            'password': 'cmd',
        }
        mock_db_cls.return_value.get_shells.return_value = [shell]
        mgr = ShellManager()

        with patch('requests.get') as mock_get:
            mock_resp = MagicMock()
            mock_resp.text = 'output'
            mock_get.return_value = mock_resp

            mgr.execute_command('s2', 'id', shell)
            called_url = mock_get.call_args[0][0]
            self.assertIn('&cmd=id', called_url)

    @patch('modules.shell.manager.Database')
    def test_execute_command_encodes_special_chars(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        shell = {
            'shell_id': 's3',
            'url': 'http://target.com/shell.php',
            'password': 'cmd',
        }
        mock_db_cls.return_value.get_shells.return_value = [shell]
        mgr = ShellManager()

        with patch('requests.get') as mock_get:
            mock_resp = MagicMock()
            mock_resp.text = ''
            mock_get.return_value = mock_resp

            mgr.execute_command('s3', 'cat /etc/passwd', shell)
            called_url = mock_get.call_args[0][0]
            self.assertIn('cat%20', called_url)

    @patch('modules.shell.manager.Database')
    def test_execute_command_shell_not_found(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        mock_db_cls.return_value.get_shells.return_value = []
        mgr = ShellManager()
        result = mgr.execute_command('nonexistent', 'ls')
        self.assertIn('not found', result.lower().replace('\x1b', '').replace('[', ''))

    @patch('modules.shell.manager.Database')
    def test_execute_command_network_error(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        shell = {
            'shell_id': 's4',
            'url': 'http://target.com/shell.php',
            'password': 'cmd',
        }
        mock_db_cls.return_value.get_shells.return_value = [shell]
        mgr = ShellManager()

        with patch('requests.get', side_effect=ConnectionError('timeout')):
            result = mgr.execute_command('s4', 'whoami', shell)
            self.assertIn('failed', result.lower().replace('\x1b', '').replace('[', ''))

    @patch('modules.shell.manager.Database')
    def test_execute_command_updates_last_used(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        shell = {
            'shell_id': 's5',
            'url': 'http://target.com/shell.php',
            'password': 'cmd',
        }
        mock_db = mock_db_cls.return_value
        mock_db.get_shells.return_value = [shell]
        mgr = ShellManager()

        with patch('requests.get') as mock_get:
            mock_resp = MagicMock()
            mock_resp.text = 'ok'
            mock_get.return_value = mock_resp

            mgr.execute_command('s5', 'ls', shell)
            mock_db.update_shell.assert_called_once()
            call_kwargs = mock_db.update_shell.call_args
            self.assertEqual(call_kwargs[0][0], 's5')

    @patch('modules.shell.manager.Database')
    def test_execute_command_prefix_match(self, mock_db_cls):
        """Shell lookup by prefix works."""
        from modules.shell.manager import ShellManager
        shell = {
            'shell_id': 'abcdef123456',
            'url': 'http://target.com/shell.php',
            'password': 'cmd',
        }
        mock_db_cls.return_value.get_shells.return_value = [shell]
        mgr = ShellManager()

        with patch('requests.get') as mock_get:
            mock_resp = MagicMock()
            mock_resp.text = 'ok'
            mock_get.return_value = mock_resp

            result = mgr.execute_command('abcdef', 'ls')
            self.assertEqual(result, 'ok')


# ===========================================================================
# ShellManager – Shell Removal (interactive_shell not found)
# ===========================================================================

class TestShellManagerShellNotFound(unittest.TestCase):

    @patch('modules.shell.manager.Database')
    def test_interactive_shell_not_found(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        mock_db_cls.return_value.get_shells.return_value = []
        mgr = ShellManager()
        # Should not raise
        mgr.interactive_shell('nonexistent')


# ===========================================================================
# ShellManager – Error Handling
# ===========================================================================

class TestShellManagerErrorHandling(unittest.TestCase):

    @patch('modules.shell.manager.Database')
    def test_custom_password_param(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        shell = {
            'shell_id': 'pw1',
            'url': 'http://target.com/shell.php',
            'password': 'exec',
        }
        mock_db_cls.return_value.get_shells.return_value = [shell]
        mgr = ShellManager()

        with patch('requests.get') as mock_get:
            mock_resp = MagicMock()
            mock_resp.text = 'result'
            mock_get.return_value = mock_resp

            mgr.execute_command('pw1', 'id', shell)
            called_url = mock_get.call_args[0][0]
            self.assertIn('exec=id', called_url)

    @patch('modules.shell.manager.Database')
    def test_execute_with_no_shell_arg_and_no_match(self, mock_db_cls):
        from modules.shell.manager import ShellManager
        mock_db_cls.return_value.get_shells.return_value = []
        mgr = ShellManager()
        result = mgr.execute_command('xxx', 'ls')
        # Should return error message, not crash
        self.assertIsInstance(result, str)

    @patch('modules.shell.manager.Database')
    def test_download_file_error(self, mock_db_cls):
        """_download_file handles errors gracefully."""
        from modules.shell.manager import ShellManager
        shell = {
            'shell_id': 'dl1',
            'url': 'http://target.com/shell.php',
            'password': 'cmd',
        }
        mock_db_cls.return_value.get_shells.return_value = [shell]
        mgr = ShellManager()

        with patch.object(mgr, 'execute_command', side_effect=Exception('fail')):
            # Should not raise
            mgr._download_file(shell, '/etc/passwd')


if __name__ == '__main__':
    unittest.main()
