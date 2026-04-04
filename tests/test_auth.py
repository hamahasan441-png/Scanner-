#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for core/auth.py — Authentication & RBAC system."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.auth import (
    UserStore, TokenManager, User,
    hash_password, verify_password, validate_password_strength,
    generate_api_key, hash_api_key,
    ROLES, PERMISSIONS, AUTH_SECRET,
)


class TestPasswordHashing(unittest.TestCase):
    """Test PBKDF2-SHA256 password hashing."""

    def test_hash_and_verify(self):
        pw = 'StrongPass1!'
        h = hash_password(pw)
        self.assertTrue(verify_password(pw, h))

    def test_wrong_password_fails(self):
        h = hash_password('Correct1!')
        self.assertFalse(verify_password('Wrong1!', h))

    def test_hash_format(self):
        h = hash_password('Test1234')
        self.assertTrue(h.startswith('pbkdf2:sha256:'))
        self.assertEqual(len(h.split('$')), 3)

    def test_different_hashes_for_same_password(self):
        h1 = hash_password('Same1234')
        h2 = hash_password('Same1234')
        self.assertNotEqual(h1, h2)  # different salts

    def test_empty_password(self):
        h = hash_password('')
        self.assertTrue(verify_password('', h))

    def test_invalid_hash_format(self):
        self.assertFalse(verify_password('test', 'invalid'))
        self.assertFalse(verify_password('test', '$$$'))


class TestPasswordValidation(unittest.TestCase):
    """Test password strength validation."""

    def test_strong_password(self):
        self.assertIsNone(validate_password_strength('StrongP1'))

    def test_too_short(self):
        err = validate_password_strength('Ab1')
        self.assertIn('8 characters', err)

    def test_no_uppercase(self):
        err = validate_password_strength('alllower1')
        self.assertIn('uppercase', err)

    def test_no_lowercase(self):
        err = validate_password_strength('ALLUPPER1')
        self.assertIn('lowercase', err)

    def test_no_digit(self):
        err = validate_password_strength('NoDigitsHere')
        self.assertIn('digit', err)


class TestAPIKey(unittest.TestCase):
    """Test API key generation and hashing."""

    def test_generate_key_format(self):
        key = generate_api_key()
        self.assertTrue(key.startswith('atk_'))
        self.assertEqual(len(key), 4 + 48)  # prefix + 24 hex bytes

    def test_hash_api_key(self):
        key = generate_api_key()
        h = hash_api_key(key)
        self.assertEqual(len(h), 64)  # SHA-256 hex

    def test_unique_keys(self):
        keys = {generate_api_key() for _ in range(100)}
        self.assertEqual(len(keys), 100)


class TestTokenManager(unittest.TestCase):
    """Test JWT token creation and validation."""

    def setUp(self):
        self.tm = TokenManager(secret='test-secret-key-12345')

    def test_create_access_token(self):
        token = self.tm.create_access_token('alice', 'admin')
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 10)

    def test_validate_access_token(self):
        token = self.tm.create_access_token('bob', 'analyst')
        payload = self.tm.validate_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload['sub'], 'bob')
        self.assertEqual(payload['role'], 'analyst')

    def test_create_refresh_token(self):
        token = self.tm.create_refresh_token('carol', 'viewer')
        payload = self.tm.validate_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload['sub'], 'carol')

    def test_invalid_token_rejected(self):
        payload = self.tm.validate_token('garbage.token.here')
        self.assertIsNone(payload)

    def test_wrong_secret_rejected(self):
        token = self.tm.create_access_token('dave', 'admin')
        other_tm = TokenManager(secret='different-secret-key')
        self.assertIsNone(other_tm.validate_token(token))


class TestUser(unittest.TestCase):
    """Test User dataclass."""

    def test_admin_has_all_perms(self):
        u = User(username='admin', password_hash='x', role='admin')
        self.assertTrue(u.has_permission('scan.create'))
        self.assertTrue(u.has_permission('user.delete'))

    def test_viewer_limited(self):
        u = User(username='viewer', password_hash='x', role='viewer')
        self.assertTrue(u.has_permission('scan.read'))
        self.assertFalse(u.has_permission('scan.create'))
        self.assertFalse(u.has_permission('exploit.run'))

    def test_analyst_permissions(self):
        u = User(username='analyst', password_hash='x', role='analyst')
        self.assertTrue(u.has_permission('scan.create'))
        self.assertTrue(u.has_permission('exploit.run'))
        self.assertFalse(u.has_permission('user.delete'))


class TestUserStore(unittest.TestCase):
    """Test UserStore CRUD and authentication."""

    def setUp(self):
        self.store = UserStore()

    def test_default_admin_exists(self):
        user = self.store.get_user('admin')
        self.assertIsNotNone(user)
        self.assertEqual(user.role, 'admin')

    def test_create_user(self):
        user = self.store.create_user('testuser', 'TestPass1', 'analyst')
        self.assertIsNotNone(user)
        self.assertEqual(user.role, 'analyst')

    def test_create_duplicate_fails(self):
        self.store.create_user('dup', 'DupPass1!', 'viewer')
        result = self.store.create_user('dup', 'Other1!', 'viewer')
        self.assertIsNone(result)

    def test_create_invalid_role_fails(self):
        result = self.store.create_user('bad', 'BadPass1!', 'superadmin')
        self.assertIsNone(result)

    def test_create_weak_password_fails(self):
        result = self.store.create_user('weak', 'short', 'viewer')
        self.assertIsNone(result)

    def test_authenticate_success(self):
        self.store.create_user('auth_test', 'AuthPass1', 'analyst')
        tokens = self.store.authenticate('auth_test', 'AuthPass1')
        self.assertIsNotNone(tokens)
        self.assertIn('access_token', tokens)
        self.assertIn('refresh_token', tokens)
        self.assertEqual(tokens['role'], 'analyst')

    def test_authenticate_wrong_password(self):
        self.store.create_user('auth_fail', 'CorrectP1', 'viewer')
        tokens = self.store.authenticate('auth_fail', 'WrongPass1')
        self.assertIsNone(tokens)

    def test_authenticate_nonexistent_user(self):
        tokens = self.store.authenticate('ghost', 'Pass1234')
        self.assertIsNone(tokens)

    def test_api_key_auth(self):
        self.store.create_user('apiuser', 'ApiPass1!', 'analyst')
        key = self.store.generate_user_api_key('apiuser')
        self.assertIsNotNone(key)
        user = self.store.authenticate_api_key(key)
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'apiuser')

    def test_api_key_wrong_key_fails(self):
        user = self.store.authenticate_api_key('atk_invalid_key')
        self.assertIsNone(user)

    def test_list_users(self):
        users = self.store.list_users()
        self.assertIsInstance(users, list)
        self.assertTrue(len(users) >= 1)  # at least default admin
        self.assertNotIn('password_hash', users[0])

    def test_update_role(self):
        self.store.create_user('updater', 'UpdateP1', 'viewer')
        self.assertTrue(self.store.update_user_role('updater', 'analyst'))
        self.assertEqual(self.store.get_user('updater').role, 'analyst')

    def test_deactivate_user(self):
        self.store.create_user('deact', 'DeactPass1', 'viewer')
        self.store.deactivate_user('deact')
        tokens = self.store.authenticate('deact', 'DeactPass1')
        self.assertIsNone(tokens)  # deactivated users can't login

    def test_delete_user(self):
        self.store.create_user('delme', 'DeleteP1!', 'viewer')
        self.assertTrue(self.store.delete_user('delme'))
        self.assertIsNone(self.store.get_user('delme'))

    def test_refresh_token(self):
        self.store.create_user('refresher', 'RefreshP1', 'analyst')
        tokens = self.store.authenticate('refresher', 'RefreshP1')
        new_tokens = self.store.refresh_access_token(tokens['refresh_token'])
        self.assertIsNotNone(new_tokens)
        self.assertIn('access_token', new_tokens)

    def test_validate_request_token(self):
        self.store.create_user('requser', 'ReqPass1!', 'viewer')
        tokens = self.store.authenticate('requser', 'ReqPass1!')
        payload = self.store.validate_request_token(tokens['access_token'])
        self.assertIsNotNone(payload)
        self.assertEqual(payload['sub'], 'requser')


class TestRBACPermissions(unittest.TestCase):
    """Test that RBAC permission matrix is correct."""

    def test_all_roles_defined(self):
        for role in ROLES:
            self.assertIn(role, PERMISSIONS)

    def test_admin_superset_of_analyst(self):
        self.assertTrue(PERMISSIONS['analyst'].issubset(PERMISSIONS['admin']))

    def test_viewer_subset_of_analyst(self):
        self.assertTrue(PERMISSIONS['viewer'].issubset(PERMISSIONS['analyst']))

    def test_viewer_no_write_perms(self):
        write_actions = {'scan.create', 'scan.delete', 'exploit.run',
                         'user.create', 'user.delete'}
        for perm in write_actions:
            self.assertNotIn(perm, PERMISSIONS['viewer'])


if __name__ == '__main__':
    unittest.main()
