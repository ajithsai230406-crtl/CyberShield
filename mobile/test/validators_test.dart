// Unit Tests for CyberValidators (Email & Password)

import 'package:flutter_test/flutter_test.dart';
import 'package:cybershield/core/utils/validators.dart';

void main() {
  group('CyberValidators - Email Validation', () {
    test('rejects null or empty strings', () {
      expect(CyberValidators.validateEmail(null), contains('required'));
      expect(CyberValidators.validateEmail(''), contains('required'));
      expect(CyberValidators.validateEmail('   '), contains('required'));
    });

    test('rejects arbitrary text without email structure', () {
      expect(CyberValidators.validateEmail('hello'), isNotNull);
      expect(CyberValidators.validateEmail('notanemail'), isNotNull);
      expect(CyberValidators.validateEmail('user@'), isNotNull);
      expect(CyberValidators.validateEmail('@domain.com'), isNotNull);
      expect(CyberValidators.validateEmail('user@domain'), contains('extension'));
      expect(CyberValidators.validateEmail('user@domain.c'), contains('at least 2 characters'));
    });

    test('rejects emails containing spaces', () {
      expect(CyberValidators.validateEmail('user name@domain.com'), contains('spaces'));
      expect(CyberValidators.validateEmail('user@dom ain.com'), contains('spaces'));
    });

    test('accepts valid RFC-compliant emails', () {
      expect(CyberValidators.validateEmail('defense.officer@cybershield.org'), isNull);
      expect(CyberValidators.validateEmail('agent_007@sec-ops.gov'), isNull);
      expect(CyberValidators.validateEmail('support@company.co.uk'), isNull);
      expect(CyberValidators.validateEmail('test.user+tag@gmail.com'), isNull);
    });
  });

  group('CyberValidators - Password Strength Validation', () {
    test('enforces login minimal threshold', () {
      expect(CyberValidators.validatePassword(null, isLogin: true), contains('required'));
      expect(CyberValidators.validatePassword('123', isLogin: true), contains('at least 6 characters'));
      expect(CyberValidators.validatePassword('secret123', isLogin: true), isNull);
    });

    test('enforces strict registration requirements', () {
      expect(CyberValidators.validatePassword('short', isLogin: false), contains('8 characters'));
      expect(CyberValidators.validatePassword('alllowercase1!', isLogin: false), contains('uppercase'));
      expect(CyberValidators.validatePassword('ALLUPPERCASE1!', isLogin: false), contains('lowercase'));
      expect(CyberValidators.validatePassword('NoNumbersHere!', isLogin: false), contains('number'));
      expect(CyberValidators.validatePassword('NoSpecialSymbols123', isLogin: false), contains('special symbol'));
      expect(CyberValidators.validatePassword('CyberShield#2026', isLogin: false), isNull);
    });
  });
}

