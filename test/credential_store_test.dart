// Round-trips a PairingCredential (token included) through
// flutter_secure_storage's test platform double, exercising the real
// read/write/delete and JSON (de)serialization path this store adds.

import 'package:flutter_secure_pairing/flutter_secure_pairing.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));

  PairingCredential sample() => PairingCredential(
        credentialId: 'cred-1',
        deviceId: 'dev-0001',
        host: 'device.example',
        certFingerprint: 'ab:cd:ef',
        role: PairingRole.member,
        issuedAt: DateTime(2026, 1, 1),
        token: 'super-secret-token',
      );

  test('load() returns null when nothing has been saved yet', () async {
    final store = SecureCredentialStore();
    expect(await store.load(), isNull);
  });

  test('save() then load() round-trips every field, including the token', () async {
    final store = SecureCredentialStore();
    final original = sample();

    await store.save(original);
    final loaded = await store.load();

    expect(loaded, isNotNull);
    expect(loaded!.credentialId, original.credentialId);
    expect(loaded.deviceId, original.deviceId);
    expect(loaded.host, original.host);
    expect(loaded.certFingerprint, original.certFingerprint);
    expect(loaded.role, original.role);
    expect(loaded.issuedAt, original.issuedAt);
    // The one field toJsonSafe() deliberately omits: proves the store uses
    // toStorageJson(), not the log-safe representation.
    expect(loaded.token, 'super-secret-token');
  });

  test('clear() removes the credential', () async {
    final store = SecureCredentialStore();
    await store.save(sample());
    await store.clear();
    expect(await store.load(), isNull);
  });

  test('a second store instance reads what the first one wrote', () async {
    // Persistence goes through platform storage, not a field on the object.
    await SecureCredentialStore().save(sample());
    final loaded = await SecureCredentialStore().load();
    expect(loaded?.credentialId, 'cred-1');
  });

  test('a corrupt stored entry fails closed to unpaired instead of throwing', () async {
    FlutterSecureStorage.setMockInitialValues({
      SecureCredentialStore.defaultStorageKey: '{not valid json',
    });
    expect(await SecureCredentialStore().load(), isNull);
  });

  group('PairingCredential', () {
    test('toJsonSafe() never contains the token', () {
      final safe = sample().toJsonSafe();
      expect(safe.containsKey('token'), isFalse);
      expect(safe.values, isNot(contains('super-secret-token')));
    });

    test('an unknown or missing role fails closed to viewer', () {
      expect(PairingRoleWire.fromWire('admin'), PairingRole.viewer);
      expect(PairingRoleWire.fromWire(null), PairingRole.viewer);
      expect(PairingRoleWire.fromWire('owner'), PairingRole.owner);
    });

    test('isExpired is true only after expiresAt', () {
      final past = PairingCredential(
        credentialId: 'c',
        deviceId: 'd',
        host: 'h',
        role: PairingRole.owner,
        issuedAt: DateTime(2026),
        expiresAt: DateTime.now().subtract(const Duration(minutes: 1)),
      );
      expect(past.isExpired, isTrue);
      expect(sample().isExpired, isFalse);
    });
  });
}
