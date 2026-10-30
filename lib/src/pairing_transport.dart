// Transport for the pairing request, behind an interface so the pairing flow
// never hard-codes how it reaches the device. Tests and demos use
// [FakePairingTransport]; [HttpPairingTransport] is a reference HTTPS
// implementation of an example protocol.

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'credential.dart';
import 'pairing_target.dart';

/// Outcome of asking a device to pair.
enum PairingOutcome {
  /// The device issued a credential.
  success,

  /// No pairing window is open on the device.
  windowClosed,

  /// The device actively refused (for example, a revoked phone retrying).
  refused,

  /// The device could not be reached, or did not answer in time.
  unreachable,

  /// This phone is already paired with the device.
  alreadyPaired,
}

/// Result of a pairing attempt.
class PairingResult {
  /// What happened.
  final PairingOutcome outcome;

  /// The issued credential, present only on [PairingOutcome.success].
  final PairingCredential? credential;

  /// True when the device reported it had no previous owner.
  ///
  /// This must be surfaced to the user, not silently accepted: an unclaimed
  /// unit is expected straight out of the box, but suspicious on a device
  /// that should already belong to someone.
  final bool deviceWasUnclaimed;

  /// Optional human-readable detail.
  final String? message;

  /// Creates a result.
  const PairingResult({
    required this.outcome,
    this.credential,
    this.deviceWasUnclaimed = false,
    this.message,
  });
}

/// Sends a pairing request to a device.
abstract class PairingTransport {
  /// Sends [request] (see `PairingRequest.toJson`) to [target].
  ///
  /// Implementations must map every failure to a [PairingResult] rather than
  /// throw, so the pairing flow never crashes on a network error.
  Future<PairingResult> pair(PairingTarget target, Map<String, dynamic> request);
}

/// In-memory transport for tests, demos and UI development. Never opens a
/// socket.
class FakePairingTransport implements PairingTransport {
  /// Produces the result for each request. Defaults to issuing an owner
  /// credential.
  final FutureOr<PairingResult> Function(PairingTarget target, Map<String, dynamic> request) respond;

  /// Every request this transport received, in order.
  final List<Map<String, dynamic>> requests = [];

  /// Simulated network latency.
  final Duration latency;

  /// Creates a fake that answers with [respond].
  FakePairingTransport({
    FutureOr<PairingResult> Function(PairingTarget, Map<String, dynamic>)? respond,
    this.latency = Duration.zero,
  }) : respond = respond ?? _issueOwnerCredential;

  /// A fake that always reports [PairingOutcome.windowClosed].
  factory FakePairingTransport.windowClosed() => FakePairingTransport(
        respond: (_, __) => const PairingResult(
          outcome: PairingOutcome.windowClosed,
          message: 'No pairing window is open on the device.',
        ),
      );

  /// A fake that issues a credential and reports an unclaimed device.
  factory FakePairingTransport.unclaimedDevice({Duration latency = Duration.zero}) =>
      FakePairingTransport(
        latency: latency,
        respond: (target, request) async {
          final r = await _issueOwnerCredential(target, request);
          return PairingResult(
            outcome: r.outcome,
            credential: r.credential,
            deviceWasUnclaimed: true,
            message: 'This device reported no previous owner.',
          );
        },
      );

  @override
  Future<PairingResult> pair(PairingTarget target, Map<String, dynamic> request) async {
    requests.add(Map.unmodifiable(request));
    if (latency > Duration.zero) await Future.delayed(latency);
    return respond(target, request);
  }

  static Future<PairingResult> _issueOwnerCredential(
      PairingTarget target, Map<String, dynamic> request) async {
    return PairingResult(
      outcome: PairingOutcome.success,
      credential: PairingCredential(
        credentialId: 'fake-${DateTime.now().microsecondsSinceEpoch}',
        deviceId: target.deviceId,
        host: target.host,
        certFingerprint: target.certFingerprint,
        role: PairingRole.owner,
        issuedAt: DateTime.now(),
        token: 'FAKE-NOT-A-REAL-TOKEN',
      ),
    );
  }
}

/// Reference HTTPS transport for an example protocol:
///
/// ```
/// POST https://<host>/v1/devices/<device_id>/pair
/// Content-Type: application/json
/// <PairingRequest JSON>
///
/// 200/201 -> PairingCredential JSON (+ optional "device_was_unclaimed", "message")
/// 404/425 -> no pairing window open
/// 403     -> refused
/// 409     -> already paired
/// ```
///
/// The path is configurable with [pathBuilder]. The status-code mapping and
/// the error handling (bounded timeout, every network failure mapped to
/// [PairingOutcome.unreachable]) are the reusable part.
class HttpPairingTransport implements PairingTransport {
  final http.Client _client;

  /// Upper bound on the whole request.
  final Duration timeout;

  /// Builds the request path from the target.
  final String Function(PairingTarget target) pathBuilder;

  /// Creates a transport. Inject [client] to test without a network.
  HttpPairingTransport({
    http.Client? client,
    this.timeout = const Duration(seconds: 10),
    String Function(PairingTarget target)? pathBuilder,
  })  : _client = client ?? http.Client(),
        pathBuilder = pathBuilder ?? _defaultPath;

  static String _defaultPath(PairingTarget t) => '/v1/devices/${t.deviceId}/pair';

  @override
  Future<PairingResult> pair(PairingTarget target, Map<String, dynamic> request) async {
    final uri = Uri(
      scheme: 'https',
      host: target.host,
      path: pathBuilder(target),
    );

    http.Response response;
    try {
      response = await _client
          .post(uri, headers: const {'content-type': 'application/json'}, body: jsonEncode(request))
          .timeout(timeout);
    } on TimeoutException {
      return const PairingResult(
        outcome: PairingOutcome.unreachable,
        message: 'Timed out reaching the device. Check the network.',
      );
    } catch (_) {
      // Covers http.ClientException (connection refused, DNS failure,
      // certificate mismatch, ...): every case collapses to "unreachable"
      // for the user, but never crashes the pairing flow.
      return const PairingResult(
        outcome: PairingOutcome.unreachable,
        message: 'Could not reach the device. Check the network.',
      );
    }

    switch (response.statusCode) {
      case 200:
      case 201:
        try {
          final body = jsonDecode(response.body) as Map<String, dynamic>;
          return PairingResult(
            outcome: PairingOutcome.success,
            credential: PairingCredential.fromJson(body),
            deviceWasUnclaimed: body['device_was_unclaimed'] == true,
            message: body['message'] as String?,
          );
        } on FormatException {
          return const PairingResult(
            outcome: PairingOutcome.refused,
            message: 'The device sent back a response this app could not understand.',
          );
        }
      case 404:
      case 425: // "too early": no pairing window open yet
        return const PairingResult(
          outcome: PairingOutcome.windowClosed,
          message: 'No pairing window is open. Press the pairing button on '
              'the device, or ask its owner to open one.',
        );
      case 403:
        return const PairingResult(outcome: PairingOutcome.refused);
      case 409:
        return const PairingResult(outcome: PairingOutcome.alreadyPaired);
      default:
        return PairingResult(
          outcome: PairingOutcome.refused,
          message: 'The device returned an unexpected status (${response.statusCode}).',
        );
    }
  }
}
