#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for utils/tool_downloader.py — External Security Tools Downloader
"""

import os
import unittest
from unittest.mock import MagicMock, patch, call

from utils.tool_downloader import (
    TOOL_REGISTRY,
    ToolInfo,
    _detect_package_manager,
    _detect_platform,
    _has_cargo,
    _has_go,
    _has_pip,
    _is_tool_installed,
    check_tools,
    get_all_install_commands,
    get_install_command,
    install_all_tools,
    install_tool,
    print_tools_status,
)


class TestToolRegistry(unittest.TestCase):
    """Verify the tool registry is complete and well-formed."""

    def test_registry_has_20_tools(self):
        self.assertEqual(len(TOOL_REGISTRY), 20)

    def test_all_entries_are_tool_info(self):
        for name, info in TOOL_REGISTRY.items():
            self.assertIsInstance(info, ToolInfo, f"{name} is not ToolInfo")

    def test_all_tools_have_required_fields(self):
        for name, info in TOOL_REGISTRY.items():
            self.assertTrue(info.name, f"{name} missing name")
            self.assertTrue(info.description, f"{name} missing description")
            self.assertTrue(info.github, f"{name} missing github")
            self.assertTrue(info.category, f"{name} missing category")
            self.assertTrue(info.install_methods, f"{name} missing install_methods")

    def test_all_tools_have_github_url(self):
        for name, info in TOOL_REGISTRY.items():
            self.assertTrue(
                info.github.startswith('https://github.com/'),
                f"{name} github URL invalid: {info.github}",
            )

    def test_all_tools_have_binary_name(self):
        for name, info in TOOL_REGISTRY.items():
            self.assertTrue(info.binary_name, f"{name} missing binary_name")

    def test_tool_integrator_tools_present(self):
        """The 5 ToolIntegrator tools must be in the registry."""
        for tool in ['nmap', 'nuclei', 'nikto', 'whatweb', 'subfinder']:
            self.assertIn(tool, TOOL_REGISTRY)

    def test_recon_arsenal_tools_present(self):
        """The 15 ReconArsenal tools must be in the registry."""
        arsenal_tools = [
            'amass', 'httpx', 'katana', 'dnsx', 'ffuf', 'gau',
            'waybackurls', 'gobuster', 'feroxbuster', 'masscan',
            'rustscan', 'hakrawler', 'arjun', 'paramspider', 'dirsearch',
        ]
        for tool in arsenal_tools:
            self.assertIn(tool, TOOL_REGISTRY)

    def test_install_methods_are_valid(self):
        valid_methods = {'apt', 'brew', 'pacman', 'pkg', 'go', 'cargo', 'pip'}
        for name, info in TOOL_REGISTRY.items():
            for method in info.install_methods:
                self.assertIn(method, valid_methods,
                              f"{name} has unknown install method: {method}")

    def test_categories_are_valid(self):
        valid_categories = {
            'network_scanning', 'vulnerability_scanning', 'reconnaissance',
            'subdomain_enum', 'http_probe', 'crawler', 'url_harvest',
            'param_discovery', 'dir_bruteforce', 'port_scan',
        }
        for name, info in TOOL_REGISTRY.items():
            self.assertIn(info.category, valid_categories,
                          f"{name} has unknown category: {info.category}")


class TestToolInfoDataclass(unittest.TestCase):
    """Test ToolInfo dataclass behavior."""

    def test_binary_name_defaults_to_name(self):
        info = ToolInfo(
            name='test', description='Test', github='https://github.com/x/y',
            category='test', install_methods={'apt': 'apt install test'},
        )
        self.assertEqual(info.binary_name, 'test')

    def test_binary_name_override(self):
        info = ToolInfo(
            name='test', description='Test', github='https://github.com/x/y',
            category='test', install_methods={'apt': 'apt install test'},
            binary_name='custom',
        )
        self.assertEqual(info.binary_name, 'custom')

    def test_homepage_defaults_empty(self):
        info = ToolInfo(
            name='test', description='Test', github='https://github.com/x/y',
            category='test', install_methods={'apt': 'apt install test'},
        )
        self.assertEqual(info.homepage, '')


class TestPlatformDetection(unittest.TestCase):
    """Test platform and package manager detection."""

    @patch('utils.tool_downloader.os.path.isdir', return_value=True)
    def test_detect_termux(self, mock_isdir):
        self.assertEqual(_detect_platform(), 'termux')
        mock_isdir.assert_called_with('/data/data/com.termux')

    @patch('utils.tool_downloader.os.path.isdir', return_value=False)
    @patch('utils.tool_downloader.platform.system', return_value='Linux')
    def test_detect_linux(self, mock_sys, mock_isdir):
        self.assertEqual(_detect_platform(), 'linux')

    @patch('utils.tool_downloader.os.path.isdir', return_value=False)
    @patch('utils.tool_downloader.platform.system', return_value='Darwin')
    def test_detect_macos(self, mock_sys, mock_isdir):
        self.assertEqual(_detect_platform(), 'macos')

    @patch('utils.tool_downloader.os.path.isdir', return_value=False)
    @patch('utils.tool_downloader.platform.system', return_value='Windows')
    def test_detect_windows(self, mock_sys, mock_isdir):
        self.assertEqual(_detect_platform(), 'windows')

    @patch('utils.tool_downloader.os.path.isdir', return_value=False)
    @patch('utils.tool_downloader.platform.system', return_value='FreeBSD')
    def test_detect_unknown(self, mock_sys, mock_isdir):
        self.assertEqual(_detect_platform(), 'unknown')


class TestPackageManagerDetection(unittest.TestCase):
    """Test package manager detection."""

    @patch('utils.tool_downloader._detect_platform', return_value='termux')
    @patch('utils.tool_downloader.shutil.which')
    def test_termux_pkg(self, mock_which, mock_plat):
        mock_which.return_value = '/usr/bin/pkg'
        self.assertEqual(_detect_package_manager(), 'pkg')

    @patch('utils.tool_downloader._detect_platform', return_value='macos')
    @patch('utils.tool_downloader.shutil.which')
    def test_macos_brew(self, mock_which, mock_plat):
        mock_which.return_value = '/usr/local/bin/brew'
        self.assertEqual(_detect_package_manager(), 'brew')

    @patch('utils.tool_downloader._detect_platform', return_value='linux')
    @patch('utils.tool_downloader.shutil.which')
    def test_linux_apt(self, mock_which, mock_plat):
        def side_effect(cmd):
            return '/usr/bin/apt-get' if cmd == 'apt-get' else None
        mock_which.side_effect = side_effect
        self.assertEqual(_detect_package_manager(), 'apt')

    @patch('utils.tool_downloader._detect_platform', return_value='linux')
    @patch('utils.tool_downloader.shutil.which')
    def test_linux_pacman(self, mock_which, mock_plat):
        def side_effect(cmd):
            if cmd == 'apt-get':
                return None
            if cmd == 'pacman':
                return '/usr/bin/pacman'
            return None
        mock_which.side_effect = side_effect
        self.assertEqual(_detect_package_manager(), 'pacman')

    @patch('utils.tool_downloader._detect_platform', return_value='windows')
    def test_windows_none(self, mock_plat):
        self.assertIsNone(_detect_package_manager())


class TestToolchainDetection(unittest.TestCase):
    """Test Go/Cargo/Pip detection helpers."""

    @patch('utils.tool_downloader.shutil.which', return_value='/usr/local/go/bin/go')
    def test_has_go_true(self, mock):
        self.assertTrue(_has_go())

    @patch('utils.tool_downloader.shutil.which', return_value=None)
    def test_has_go_false(self, mock):
        self.assertFalse(_has_go())

    @patch('utils.tool_downloader.shutil.which', return_value='/usr/bin/cargo')
    def test_has_cargo_true(self, mock):
        self.assertTrue(_has_cargo())

    @patch('utils.tool_downloader.shutil.which', return_value=None)
    def test_has_cargo_false(self, mock):
        self.assertFalse(_has_cargo())

    @patch('utils.tool_downloader.shutil.which')
    def test_has_pip_true(self, mock):
        mock.side_effect = lambda x: '/usr/bin/pip' if x == 'pip' else None
        self.assertTrue(_has_pip())

    @patch('utils.tool_downloader.shutil.which', return_value=None)
    def test_has_pip_false(self, mock):
        self.assertFalse(_has_pip())


class TestIsToolInstalled(unittest.TestCase):
    """Test _is_tool_installed."""

    @patch('utils.tool_downloader.shutil.which', return_value='/usr/bin/nmap')
    def test_installed(self, mock):
        self.assertTrue(_is_tool_installed('nmap'))

    @patch('utils.tool_downloader.shutil.which', return_value=None)
    def test_not_installed(self, mock):
        self.assertFalse(_is_tool_installed('nmap'))

    @patch('utils.tool_downloader.shutil.which', return_value=None)
    def test_unknown_tool(self, mock):
        self.assertFalse(_is_tool_installed('nonexistent_tool'))


class TestGetInstallCommand(unittest.TestCase):
    """Test get_install_command selection logic."""

    def test_unknown_tool_returns_none(self):
        self.assertIsNone(get_install_command('nonexistent_tool'))

    @patch('utils.tool_downloader._detect_package_manager', return_value='apt')
    @patch('utils.tool_downloader._has_go', return_value=True)
    def test_prefers_system_pkg_manager(self, mock_go, mock_pkg):
        # nmap has apt method — should prefer it over any go method
        cmd = get_install_command('nmap')
        self.assertIn('apt-get install', cmd)

    @patch('utils.tool_downloader._detect_package_manager', return_value=None)
    @patch('utils.tool_downloader._has_go', return_value=True)
    @patch('utils.tool_downloader._has_cargo', return_value=False)
    @patch('utils.tool_downloader._has_pip', return_value=False)
    def test_falls_back_to_go(self, mock_pip, mock_cargo, mock_go, mock_pkg):
        # httpx has go method
        cmd = get_install_command('httpx')
        self.assertIn('go install', cmd)

    @patch('utils.tool_downloader._detect_package_manager', return_value=None)
    @patch('utils.tool_downloader._has_go', return_value=False)
    @patch('utils.tool_downloader._has_cargo', return_value=True)
    @patch('utils.tool_downloader._has_pip', return_value=False)
    def test_falls_back_to_cargo(self, mock_pip, mock_cargo, mock_go, mock_pkg):
        # feroxbuster has cargo method
        cmd = get_install_command('feroxbuster')
        self.assertIn('cargo install', cmd)

    @patch('utils.tool_downloader._detect_package_manager', return_value=None)
    @patch('utils.tool_downloader._has_go', return_value=False)
    @patch('utils.tool_downloader._has_cargo', return_value=False)
    @patch('utils.tool_downloader._has_pip', return_value=True)
    def test_falls_back_to_pip(self, mock_pip, mock_cargo, mock_go, mock_pkg):
        # arjun has pip method
        cmd = get_install_command('arjun')
        self.assertIn('pip install', cmd)

    @patch('utils.tool_downloader._detect_package_manager', return_value=None)
    @patch('utils.tool_downloader._has_go', return_value=False)
    @patch('utils.tool_downloader._has_cargo', return_value=False)
    @patch('utils.tool_downloader._has_pip', return_value=False)
    def test_no_method_returns_none(self, mock_pip, mock_cargo, mock_go, mock_pkg):
        # gau only has go — with nothing available, should be None
        cmd = get_install_command('gau')
        self.assertIsNone(cmd)


class TestGetAllInstallCommands(unittest.TestCase):
    """Test get_all_install_commands."""

    def test_nmap_has_multiple_methods(self):
        cmds = get_all_install_commands('nmap')
        self.assertIn('apt', cmds)
        self.assertIn('brew', cmds)

    def test_unknown_tool_returns_empty(self):
        cmds = get_all_install_commands('nonexistent_tool')
        self.assertEqual(cmds, {})

    def test_arjun_has_pip_method(self):
        cmds = get_all_install_commands('arjun')
        self.assertIn('pip', cmds)


class TestCheckTools(unittest.TestCase):
    """Test check_tools aggregation."""

    @patch('utils.tool_downloader._is_tool_installed')
    @patch('utils.tool_downloader.get_install_command')
    def test_returns_all_20_tools(self, mock_cmd, mock_installed):
        mock_installed.return_value = False
        mock_cmd.return_value = 'fake install'
        result = check_tools()
        self.assertEqual(len(result), 20)

    @patch('utils.tool_downloader._is_tool_installed', return_value=True)
    def test_installed_tool_has_no_install_cmd(self, mock):
        result = check_tools()
        for name, info in result.items():
            self.assertTrue(info['installed'])
            self.assertIsNone(info['install_cmd'])

    @patch('utils.tool_downloader._is_tool_installed', return_value=False)
    @patch('utils.tool_downloader.get_install_command', return_value='apt install test')
    def test_missing_tool_has_install_cmd(self, mock_cmd, mock_installed):
        result = check_tools()
        for name, info in result.items():
            self.assertFalse(info['installed'])
            self.assertEqual(info['install_cmd'], 'apt install test')


class TestInstallTool(unittest.TestCase):
    """Test install_tool."""

    @patch('utils.tool_downloader._is_tool_installed', return_value=True)
    def test_already_installed_returns_true(self, mock):
        self.assertTrue(install_tool('nmap', verbose=False))

    @patch('utils.tool_downloader._is_tool_installed', return_value=False)
    def test_unknown_tool_returns_false(self, mock):
        self.assertFalse(install_tool('nonexistent_tool', verbose=False))

    @patch('utils.tool_downloader._is_tool_installed')
    @patch('utils.tool_downloader.get_install_command', return_value=None)
    def test_no_install_method_returns_false(self, mock_cmd, mock_installed):
        mock_installed.return_value = False
        self.assertFalse(install_tool('nmap', verbose=False))

    @patch('utils.tool_downloader._is_tool_installed')
    @patch('utils.tool_downloader.get_install_command', return_value='apt install nmap')
    @patch('utils.tool_downloader.subprocess.run')
    def test_successful_install(self, mock_run, mock_cmd, mock_installed):
        mock_installed.side_effect = [False, True]  # not installed, then installed
        mock_run.return_value = MagicMock(returncode=0, stderr='')
        self.assertTrue(install_tool('nmap', verbose=False))

    @patch('utils.tool_downloader._is_tool_installed')
    @patch('utils.tool_downloader.get_install_command', return_value='apt install nmap')
    @patch('utils.tool_downloader.subprocess.run')
    def test_failed_install(self, mock_run, mock_cmd, mock_installed):
        mock_installed.side_effect = [False, False]  # not installed before and after
        mock_run.return_value = MagicMock(returncode=1, stderr='error msg')
        self.assertFalse(install_tool('nmap', verbose=False))

    @patch('utils.tool_downloader._is_tool_installed', return_value=False)
    @patch('utils.tool_downloader.get_install_command', return_value='apt install nmap')
    @patch('utils.tool_downloader.subprocess.run')
    def test_timeout_returns_false(self, mock_run, mock_cmd, mock_installed):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='apt', timeout=600)
        self.assertFalse(install_tool('nmap', verbose=False))

    @patch('utils.tool_downloader._is_tool_installed', return_value=False)
    @patch('utils.tool_downloader.get_install_command', return_value='apt install nmap')
    @patch('utils.tool_downloader.subprocess.run')
    def test_exception_returns_false(self, mock_run, mock_cmd, mock_installed):
        mock_run.side_effect = OSError("Permission denied")
        self.assertFalse(install_tool('nmap', verbose=False))


class TestInstallAllTools(unittest.TestCase):
    """Test install_all_tools."""

    @patch('utils.tool_downloader._is_tool_installed', return_value=True)
    def test_all_installed_skips(self, mock):
        result = install_all_tools(verbose=False)
        self.assertEqual(len(result), 20)
        self.assertTrue(all(result.values()))

    @patch('utils.tool_downloader.install_tool', return_value=True)
    @patch('utils.tool_downloader._is_tool_installed', return_value=False)
    def test_installs_missing_tools(self, mock_installed, mock_install):
        result = install_all_tools(verbose=False)
        self.assertEqual(len(result), 20)
        self.assertEqual(mock_install.call_count, 20)


class TestPrintToolsStatus(unittest.TestCase):
    """Test print_tools_status output."""

    @patch('utils.tool_downloader.check_tools')
    def test_prints_without_error(self, mock_check):
        mock_check.return_value = {
            'nmap': {
                'installed': True,
                'description': 'Network scanner',
                'category': 'network_scanning',
                'github': 'https://github.com/nmap/nmap',
                'install_cmd': None,
            },
            'nuclei': {
                'installed': False,
                'description': 'Vuln scanner',
                'category': 'vulnerability_scanning',
                'github': 'https://github.com/projectdiscovery/nuclei',
                'install_cmd': 'go install nuclei@latest',
            },
        }
        # Should not raise
        print_tools_status()

    @patch('utils.tool_downloader.check_tools')
    def test_all_installed_message(self, mock_check):
        mock_check.return_value = {
            name: {
                'installed': True,
                'description': info.description,
                'category': info.category,
                'github': info.github,
                'install_cmd': None,
            }
            for name, info in TOOL_REGISTRY.items()
        }
        # Should not raise
        print_tools_status()


class TestInstallMethodPreference(unittest.TestCase):
    """Verify platform-specific install method preference."""

    @patch('utils.tool_downloader._detect_package_manager', return_value='brew')
    @patch('utils.tool_downloader._has_go', return_value=True)
    def test_brew_preferred_over_go_on_macos(self, mock_go, mock_pkg):
        # nuclei has both brew and go — brew should be preferred
        cmd = get_install_command('nuclei')
        self.assertIn('brew install', cmd)

    @patch('utils.tool_downloader._detect_package_manager', return_value='apt')
    @patch('utils.tool_downloader._has_go', return_value=True)
    def test_apt_preferred_over_go_on_linux(self, mock_go, mock_pkg):
        # ffuf has both apt and go — apt should be preferred
        cmd = get_install_command('ffuf')
        self.assertIn('apt-get install', cmd)

    @patch('utils.tool_downloader._detect_package_manager', return_value='pkg')
    @patch('utils.tool_downloader._has_go', return_value=False)
    @patch('utils.tool_downloader._has_cargo', return_value=False)
    @patch('utils.tool_downloader._has_pip', return_value=False)
    def test_pkg_used_on_termux(self, mock_pip, mock_cargo, mock_go, mock_pkg):
        cmd = get_install_command('nmap')
        self.assertIn('pkg install', cmd)


if __name__ == '__main__':
    unittest.main()
