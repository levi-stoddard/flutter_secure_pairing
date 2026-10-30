// Persistence for the issued credential. Never plain SharedPreferences, which
// is readable on a rooted device or from a backup extraction.

import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'credential.dart';

/// Stores the credential issued at pairing.
abstract class CredentialStore {
  /// Returns the stored credential, or null if there is none.
  Future<PairingCredential?> load();

  /// Replaces the stored credential.
  Future<void> save(PairingCredential c);

  /// Removes the stored credential.
  Future<void> clear();
}

/// A non-persistent store for tests and examples.
class InMemoryCredentialStore implements CredentialStore {
  PairingCredential? _c;

  @override
  Future<PairingCredential?> load() async => _c;

  @override
  Future<void> save(PairingCredential c) async => _c = c;

  @override
  Future<void> clear() async => _c = null;
}

/// Credential persistence backed by [FlutterSecureStorage] (Android Keystore
/// via encrypted shared preferences; iOS Keychain).
///
/// The token is the actual secret; the rest of the credential is stored
/// alongside it in one JSON blob, since it is always read and written as a
/// unit.
class SecureCredentialStore implements CredentialStore {
  /// Default secure-storage key for the credential blob.
  static const defaultStorageKey = 'flutter_secure_pairing.credential.v1';

  final FlutterSecureStorage _storage;

  /// The secure-storage key used by this instance.
  final String storageKey;

  /// Creates a store backed by [storage].
  SecureCredentialStore({FlutterSecureStorage? storage, this.storageKey = defaultStorageKey})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
            );

  @override
  Future<PairingCredential?> load() async {
    final raw = await _storage.read(key: storageKey);
    if (raw == null) return null;
    try {
      return PairingCredential.fromJson(jsonDecode(raw) as Map<String, dynamic>);
    } on FormatException {
      // Corrupt or unreadable entry: fail closed to "unpaired" rather than
      // crash on launch.
      return null;
    }
  }

  @override
  Future<void> save(PairingCredential c) async {
    await _storage.write(key: storageKey, value: jsonEncode(c.toStorageJson()));
  }

  @override
  Future<void> clear() async => _storage.delete(key: storageKey);
}
