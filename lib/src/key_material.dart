// Device key material for pairing.
//
// The private key is generated on the device, persisted only through
// platform secure storage, and never returned by any public API. Only the
// public key (PEM), a fingerprint of it, and a CSR signed by it ever leave
// this class.

import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Abstraction over the device's pairing keypair.
///
/// Callers can ask for the public key and things derived from it, but there
/// is deliberately no way to read the private key. That keeps the door open
/// for a hardware-bound implementation (Android StrongBox / iOS Secure
/// Enclave) without changing any caller.
abstract class KeyMaterial {
  /// Creates the keypair on first use, or restores it from storage.
  ///
  /// Idempotent: calling it again never replaces an existing key.
  Future<void> ensureKeypair();

  /// The public key as a SubjectPublicKeyInfo PEM block (RFC 5480).
  Future<String> publicKeyPem();
}

/// A NIST P-256 keypair generated with `basic_utils`/`pointycastle`, with the
/// private key persisted through [FlutterSecureStorage] (Android
/// EncryptedSharedPreferences backed by the Keystore; iOS Keychain).
///
/// The private key is generated once, PEM-encoded and written to secure
/// storage, so it survives app restarts without ever touching plain storage
/// or crossing the network.
///
/// What this does NOT do: the key is generated in Dart and encrypted at rest
/// by the OS keystore. It is not hardware-bound or non-exportable the way a
/// key generated inside StrongBox or the Secure Enclave is. See the README's
/// limitations section.
class SecureKeyMaterial implements KeyMaterial {
  /// Default secure-storage key under which the private key PEM is stored.
  static const defaultStorageKey = 'flutter_secure_pairing.device_private_key.v1';

  final FlutterSecureStorage _storage;

  /// The secure-storage key used by this instance.
  final String storageKey;

  ECPrivateKey? _private;
  ECPublicKey? _public;
  String? _publicPem;

  /// Creates key material backed by [storage] (defaults to
  /// [FlutterSecureStorage] with encrypted shared preferences on Android).
  SecureKeyMaterial({FlutterSecureStorage? storage, this.storageKey = defaultStorageKey})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
            );

  @override
  Future<void> ensureKeypair() async {
    if (_private != null) return;

    final existing = await _storage.read(key: storageKey);
    if (existing != null) {
      _private = CryptoUtils.ecPrivateKeyFromPem(existing);
      _public = _publicFromPrivate(_private!);
      _publicPem = CryptoUtils.encodeEcPublicKeyToPem(_public!);
      return;
    }

    final pair = CryptoUtils.generateEcKeyPair(curve: 'prime256v1');
    _private = pair.privateKey as ECPrivateKey;
    _public = pair.publicKey as ECPublicKey;
    _publicPem = CryptoUtils.encodeEcPublicKeyToPem(_public!);

    await _storage.write(
      key: storageKey,
      value: CryptoUtils.encodeEcPrivateKeyToPem(_private!),
    );
  }

  @override
  Future<String> publicKeyPem() async {
    await ensureKeypair();
    return _publicPem!;
  }

  /// SHA-256 over the DER-encoded public key, as colon-separated uppercase
  /// hex. Suitable for showing to a user to compare against what the other
  /// side displays.
  Future<String> publicKeyFingerprint() async {
    final pem = await publicKeyPem();
    final der = CryptoUtils.getBytesFromPEMString(pem);
    final digest = CryptoUtils.getHash(Uint8List.fromList(der), algorithmName: 'SHA-256');
    final hex = digest.toUpperCase();
    final pairs = <String>[];
    for (var i = 0; i < hex.length; i += 2) {
      pairs.add(hex.substring(i, i + 2));
    }
    return pairs.join(':');
  }

  /// A PKCS#10 certificate signing request for this keypair, signed with
  /// ECDSA/SHA-256, for flows where the other side issues a certificate
  /// (for example, a later move to mutual TLS).
  ///
  /// The private key is used to sign inside this class; it is never returned.
  Future<String> csrPem({required String commonName}) async {
    await ensureKeypair();
    return X509Utils.generateEccCsrPem({'CN': commonName}, _private!, _public!);
  }

  // basic_utils' PEM decode only returns the private scalar; re-derive Q
  // (the public point) from it so a restored key can still report its
  // public PEM without needing it stored separately.
  ECPublicKey _publicFromPrivate(ECPrivateKey private) {
    final q = private.parameters!.G * private.d;
    return ECPublicKey(q, private.parameters);
  }
}
