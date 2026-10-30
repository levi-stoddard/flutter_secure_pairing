// Proves a real NIST P-256 EC keypair is generated (not a placeholder),
// persisted through flutter_secure_storage's test platform double, and that
// the public key derived from a restored private key matches the original.

import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:flutter_secure_pairing/flutter_secure_pairing.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));

  test('publicKeyPem() returns a real EC SubjectPublicKeyInfo PEM block', () async {
    final km = SecureKeyMaterial();
    final pem = await km.publicKeyPem();

    // Standard SubjectPublicKeyInfo PEM framing (RFC 5480); the curve
    // identity lives inside the DER, which the decode step below verifies.
    expect(pem, startsWith('-----BEGIN PUBLIC KEY-----'));
    expect(pem, contains('-----END PUBLIC KEY-----'));

    // Round-trips through basic_utils' own decoder as a genuine P-256 key,
    // not just a string that happens to look PEM-shaped.
    final decoded = CryptoUtils.ecPublicKeyFromPem(pem);
    expect(decoded.parameters?.domainName, 'prime256v1');
    expect(decoded.Q, isNotNull);
  });

  test('ensureKeypair() is idempotent: same key, not regenerated each call', () async {
    final km = SecureKeyMaterial();
    await km.ensureKeypair();
    final first = await km.publicKeyPem();
    await km.ensureKeypair();
    final second = await km.publicKeyPem();

    expect(first, second);
  });

  test('the private key persists through secure storage, not an in-memory field', () async {
    final first = SecureKeyMaterial();
    final pubFromFirst = await first.publicKeyPem();

    // A second instance over the same (mocked) secure storage reads the
    // persisted key instead of generating its own, which would break
    // pairing across app restarts.
    final second = SecureKeyMaterial();
    final pubFromSecond = await second.publicKeyPem();

    expect(pubFromSecond, pubFromFirst);
  });

  test("a restored key's public PEM matches the one generated on first use", () async {
    const storage = FlutterSecureStorage();
    final first = SecureKeyMaterial(storage: storage);
    await first.ensureKeypair();
    final generatedPem = await first.publicKeyPem();

    // Simulates an app restart: a fresh instance over storage that already
    // holds a key must derive the SAME public key from the persisted scalar.
    final restored = SecureKeyMaterial(storage: storage);
    final restoredPem = await restored.publicKeyPem();

    expect(restoredPem, generatedPem);

    // A broken d*G derivation could produce the point at infinity.
    final ECPublicKey decoded = CryptoUtils.ecPublicKeyFromPem(restoredPem);
    expect(decoded.Q!.isInfinity, isFalse);
  });

  test('the stored secret is the private key PEM, and only under its storage key', () async {
    const storage = FlutterSecureStorage();
    await SecureKeyMaterial(storage: storage).ensureKeypair();

    final all = await storage.readAll();
    expect(all.keys, [SecureKeyMaterial.defaultStorageKey]);
    expect(all.values.single, contains('PRIVATE KEY'));
  });

  test('separate storage keys hold independent keypairs', () async {
    final a = SecureKeyMaterial(storageKey: 'a');
    final b = SecureKeyMaterial(storageKey: 'b');
    expect(await a.publicKeyPem(), isNot(await b.publicKeyPem()));
  });

  test('publicKeyFingerprint() is a stable SHA-256 over the public key', () async {
    final km = SecureKeyMaterial();
    final fp = await km.publicKeyFingerprint();

    expect(fp, matches(RegExp(r'^([0-9A-F]{2}:){31}[0-9A-F]{2}$')));
    expect(await SecureKeyMaterial().publicKeyFingerprint(), fp);
  });

  test('csrPem() produces a CSR whose public key is this device key', () async {
    final km = SecureKeyMaterial();
    final csr = await km.csrPem(commonName: 'test-phone');

    expect(csr, startsWith('-----BEGIN CERTIFICATE REQUEST-----'));
    final parsed = X509Utils.csrFromPem(csr);
    expect(parsed.certificationRequestInfo?.subject?['2.5.4.3'], 'test-phone');

    // basic_utils exposes the CSR's SubjectPublicKeyInfo DER as a hex string.
    final hex = parsed.certificationRequestInfo!.publicKeyInfo!.bytes!;
    final der = Uint8List.fromList([
      for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16),
    ]);
    final csrKey = CryptoUtils.ecPublicKeyFromDerBytes(der);
    final deviceKey = CryptoUtils.ecPublicKeyFromPem(await km.publicKeyPem());
    expect(csrKey.Q, deviceKey.Q);
  });
}
