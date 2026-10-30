// Exercises HttpPairingTransport's real request construction, status-code
// mapping and timeout handling through an injected http.Client
// (package:http/testing.dart's MockClient). No device is needed: the
// client-side logic is fully real and fully testable without one.

import 'dart:convert';

import 'package:flutter_secure_pairing/flutter_secure_pairing.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  const target = PairingTarget(deviceId: 'dev-0001', host: 'device.example');
  const request = {'device_id': 'dev-0001', 'display_name': 'Test Phone'};

  test('sends a real HTTPS POST to /v1/devices/{deviceId}/pair with the JSON body', () async {
    http.Request? captured;
    final transport = HttpPairingTransport(
      client: MockClient((req) async {
        captured = req;
        return http.Response(
          jsonEncode({
            'credential_id': 'cred-1',
            'device_id': 'dev-0001',
            'host': 'device.example',
            'role': 'owner',
            'issued_at': DateTime.now().toIso8601String(),
            'token': 'secret-token',
          }),
          200,
        );
      }),
    );

    final result = await transport.pair(target, request);

    expect(captured, isNotNull);
    expect(captured!.url.scheme, 'https');
    expect(captured!.url.host, 'device.example');
    expect(captured!.url.path, '/v1/devices/dev-0001/pair');
    expect(captured!.headers['content-type'], startsWith('application/json'));
    expect(jsonDecode(captured!.body), request);

    expect(result.outcome, PairingOutcome.success);
    expect(result.credential?.credentialId, 'cred-1');
    expect(result.credential?.token, 'secret-token');
    expect(result.credential?.role, PairingRole.owner);
  });

  test('pathBuilder overrides the request path', () async {
    Uri? url;
    final transport = HttpPairingTransport(
      pathBuilder: (t) => '/custom/${t.deviceId}',
      client: MockClient((req) async {
        url = req.url;
        return http.Response('', 403);
      }),
    );
    await transport.pair(target, request);
    expect(url?.path, '/custom/dev-0001');
  });

  test('maps device_was_unclaimed through from the response body', () async {
    final transport = HttpPairingTransport(
      client: MockClient((req) async => http.Response(
            jsonEncode({
              'credential_id': 'cred-2',
              'device_id': 'dev-0001',
              'host': 'device.example',
              'role': 'owner',
              'issued_at': DateTime.now().toIso8601String(),
              'device_was_unclaimed': true,
            }),
            200,
          )),
    );

    final result = await transport.pair(target, request);
    expect(result.deviceWasUnclaimed, isTrue);
  });

  test('maps 404 (no pairing window) to windowClosed', () async {
    final transport = HttpPairingTransport(
      client: MockClient((req) async => http.Response('', 404)),
    );
    final result = await transport.pair(target, request);
    expect(result.outcome, PairingOutcome.windowClosed);
  });

  test('maps 425 (too early) to windowClosed', () async {
    final transport = HttpPairingTransport(
      client: MockClient((req) async => http.Response('', 425)),
    );
    final result = await transport.pair(target, request);
    expect(result.outcome, PairingOutcome.windowClosed);
  });

  test('maps 403 to refused', () async {
    final transport = HttpPairingTransport(
      client: MockClient((req) async => http.Response('', 403)),
    );
    final result = await transport.pair(target, request);
    expect(result.outcome, PairingOutcome.refused);
  });

  test('maps 409 to alreadyPaired', () async {
    final transport = HttpPairingTransport(
      client: MockClient((req) async => http.Response('', 409)),
    );
    final result = await transport.pair(target, request);
    expect(result.outcome, PairingOutcome.alreadyPaired);
  });

  test('maps an unexpected status to refused with the code in the message', () async {
    final transport = HttpPairingTransport(
      client: MockClient((req) async => http.Response('', 500)),
    );
    final result = await transport.pair(target, request);
    expect(result.outcome, PairingOutcome.refused);
    expect(result.message, contains('500'));
  });

  test('a real timeout maps to unreachable, not an uncaught exception', () async {
    final transport = HttpPairingTransport(
      timeout: const Duration(milliseconds: 50),
      client: MockClient((req) async {
        await Future.delayed(const Duration(seconds: 5));
        return http.Response('', 200);
      }),
    );
    final result = await transport.pair(target, request);
    expect(result.outcome, PairingOutcome.unreachable);
  });

  test('a connection error maps to unreachable, not an uncaught exception', () async {
    final transport = HttpPairingTransport(
      client: MockClient((req) async => throw http.ClientException('connection refused')),
    );
    final result = await transport.pair(target, request);
    expect(result.outcome, PairingOutcome.unreachable);
  });

  test('an unparseable 200 body is treated as refused, not a crash', () async {
    final transport = HttpPairingTransport(
      client: MockClient((req) async => http.Response('not json', 200)),
    );
    final result = await transport.pair(target, request);
    expect(result.outcome, PairingOutcome.refused);
  });
}
