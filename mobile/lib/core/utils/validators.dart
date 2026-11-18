// CyberShield Input Validation Utilities

class CyberValidators {
  static final RegExp _strictEmailRegExp = RegExp(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$",
  );

  /// Validates email address strictly according to RFC standards.
  /// Rejects empty strings, arbitrary text, missing domain/TLD, and spaces.
  static String? validateEmail(String? value) {
    if (value == null || value.trim().isEmpty) {
      return 'Security email is required';
    }

    final trimmed = value.trim();

    if (trimmed.length < 5 || trimmed.length > 254) {
      return 'Email must be between 5 and 254 characters';
    }

    if (trimmed.contains(' ')) {
      return 'Email cannot contain spaces';
    }

    if (!trimmed.contains('@')) {
      return 'Email must contain an @ symbol';
    }

    final parts = trimmed.split('@');
    if (parts.length != 2 || parts[0].isEmpty || parts[1].isEmpty) {
      return 'Enter a valid email address (e.g. agent@cybershield.org)';
    }

    final domain = parts[1];
    if (!domain.contains('.') || domain.startsWith('.') || domain.endsWith('.')) {
      return 'Domain must include a valid extension (e.g. .com, .org)';
    }

    final tld = domain.split('.').last;
    if (tld.length < 2) {
      return 'Domain extension must be at least 2 characters';
    }

    if (!_strictEmailRegExp.hasMatch(trimmed)) {
      return 'Invalid email syntax. Please check for typos';
    }

    return null;
  }

  /// Validates defense password strength.
  /// Enforces min 8 characters, uppercase, lowercase, digit, and special symbol.
  static String? validatePassword(String? value, {bool isLogin = false}) {
    if (value == null || value.isEmpty) {
      return 'Defense password is required';
    }

    if (isLogin) {
      if (value.length < 6) {
        return 'Password must be at least 6 characters';
      }
      return null;
    }

    if (value.length < 8) {
      return 'Password must be at least 8 characters';
    }
    if (!RegExp(r'[A-Z]').hasMatch(value)) {
      return 'Include at least one uppercase letter (A-Z)';
    }
    if (!RegExp(r'[a-z]').hasMatch(value)) {
      return 'Include at least one lowercase letter (a-z)';
    }
    if (!RegExp(r'[0-9]').hasMatch(value)) {
      return 'Include at least one number (0-9)';
    }
    if (!RegExp(r'[!@#$%^&*(),.?":{}|<>_\-+=]').hasMatch(value)) {
      return 'Include at least one special symbol (!@#\$%^&*)';
    }

    return null;
  }
}

