import 'package:basic_utils/basic_utils.dart';
import 'package:flutter_secure_pairing/flutter_secure_pairing.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));

  const target = PairingTarget(deviceId: 'dev-0001', host: 'device.local');

  test('sends only the public key, and persists the issued credential', () async {
    final transport = FakePairingTransport();
    final store = InMemoryCredentialStore();
    final service = PairingService(transport: transport, store: store);

    final result = await service.pair(target, displayName: 'Test Phone');

    expect(result.outcome, PairingOutcome.success);
    expect(service.isPaired, isTrue);
    expect(service.role, PairingRole.owner);
    expect((await store.load())?.credentialId, result.credential!.credentialId);

    final sent = transport.requests.single;
    expect(sent['device_id'], 'dev-0001');
    expect(sent['display_name'], 'Test Phone');
    expect(sent['auth_method'], 'bearer');
    expect(sent['public_key'], startsWith('-----BEGIN PUBLIC KEY-----'));
    expect(CryptoUtils.ecPublicKeyFromPem(sent['public_key']).Q, isNotNull);
    expect(sent.values.whereType<String>().any((v) => v.contains('PRIVATE KEY')), isFalse);
  });

  test('a failed pairing stores nothing and stays unpaired', () async {
    final store = InMemoryCredentialStore();
    final service = PairingService(transport: FakePairingTransport.windowClosed(), store: store);

    final result = await service.pair(target);

    expect(result.outcome, PairingOutcome.windowClosed);
    expect(service.isPaired, isFalse);
    expect(service.role, PairingRole.viewer);
    expect(await store.load(), isNull);
  });

  test('an unclaimed-device report is passed through to the caller', () async {
    final service = PairingService(
      transport: FakePairingTransport.unclaimedDevice(),
      store: InMemoryCredentialStore(),
    );
    final result = await service.pair(target);
    expect(result.deviceWasUnclaimed, isTrue);
  });

  test('the same device key is reused across pairings', () async {
    final transport = FakePairingTransport();
    final service = PairingService(transport: transport, store: InMemoryCredentialStore());
    await service.pair(target);
    await service.pair(target);
    expect(transport.requests[0]['public_key'], transport.requests[1]['public_key']);
  });

  test('busy is true only while the request is in flight', () async {
    final service = PairingService(
      transport: FakePairingTransport(latency: const Duration(milliseconds: 20)),
      store: InMemoryCredentialStore(),
    );
    final future = service.pair(target);
    await Future<void>.delayed(const Duration(milliseconds: 5));
    expect(service.busy, isTrue);
    await future;
    expect(service.busy, isFalse);
  });

  test('restore() reloads a stored credential; unpair() clears it', () async {
    final store = SecureCredentialStore();
    await PairingService(transport: FakePairingTransport(), store: store).pair(target);

    final restarted = PairingService(transport: FakePairingTransport(), store: store);
    expect(restarted.isPaired, isFalse);
    await restarted.restore();
    expect(restarted.isPaired, isTrue);

    await restarted.unpair();
    expect(restarted.isPaired, isFalse);
    expect(await store.load(), isNull);
  });

  test('an expired credential fails closed to viewer', () async {
    final service = PairingService(
      store: InMemoryCredentialStore(),
      transport: FakePairingTransport(
        respond: (t, _) => PairingResult(
          outcome: PairingOutcome.success,
          credential: PairingCredential(
            credentialId: 'c',
            deviceId: t.deviceId,
            host: t.host,
            role: PairingRole.owner,
            issuedAt: DateTime(2026),
            expiresAt: DateTime.now().subtract(const Duration(seconds: 1)),
          ),
        ),
      ),
    );
    await service.pair(target);
    expect(service.isPaired, isFalse);
    expect(service.role, PairingRole.viewer);
  });

  test('PairingRequest.toJson() uses the documented field names', () {
    const r = PairingRequest(deviceId: 'd', displayName: 'n', publicKeyPem: 'pem');
    expect(r.toJson().keys,
        unorderedEquals(['device_id', 'display_name', 'public_key', 'auth_method', 'client_version']));
  });
}
