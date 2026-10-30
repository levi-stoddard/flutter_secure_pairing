import 'package:flutter_secure_pairing/flutter_secure_pairing.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('parses a well-formed payload', () {
    final t = PairingTarget.tryParse('securepair://pair?d=dev-0001&h=device.local&f=ab:cd');
    expect(t, isNotNull);
    expect(t!.deviceId, 'dev-0001');
    expect(t.host, 'device.local');
    expect(t.certFingerprint, 'ab:cd');
  });

  test('the fingerprint is optional', () {
    final t = PairingTarget.tryParse('securepair://pair?d=dev-0001&h=device.local');
    expect(t?.certFingerprint, isNull);
  });

  test('trims surrounding whitespace from scanned text', () {
    expect(PairingTarget.tryParse('  securepair://pair?d=x&h=y\n'), isNotNull);
  });

  test('rejects the wrong scheme, wrong action, or missing fields', () {
    for (final raw in [
      'https://pair?d=x&h=y',
      'securepair://unpair?d=x&h=y',
      'securepair://pair?h=y',
      'securepair://pair?d=x',
      'securepair://pair?d=&h=y',
      'securepair://pair?d=x&h=',
      'not a uri at all',
      '',
    ]) {
      expect(PairingTarget.tryParse(raw), isNull, reason: raw);
    }
  });

  test('a custom scheme must match exactly', () {
    const raw = 'acme://pair?d=x&h=y';
    expect(PairingTarget.tryParse(raw), isNull);
    expect(PairingTarget.tryParse(raw, scheme: 'acme'), isNotNull);
  });

  test('toUri() round-trips through tryParse()', () {
    const t = PairingTarget(deviceId: 'dev 1', host: '192.168.4.1', certFingerprint: 'AA:BB');
    final parsed = PairingTarget.tryParse(t.toUri().toString());
    expect(parsed?.deviceId, 'dev 1');
    expect(parsed?.host, '192.168.4.1');
    expect(parsed?.certFingerprint, 'AA:BB');
  });

  test('the payload carries no credential fields', () {
    const t = PairingTarget(deviceId: 'd', host: 'h');
    expect(t.toUri().queryParameters.keys, unorderedEquals(['d', 'h']));
  });
}
