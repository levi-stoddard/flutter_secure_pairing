// The credential a device issues to a phone at pairing.
//
// Role checks on the phone are a UX affordance, not a security boundary: the
// device is the authority and must re-check every request. A modified client
// can bypass anything enforced only on the phone.

/// Privilege level granted by the device at pairing.
enum PairingRole {
  /// Read-only access. The least-privileged role and the fail-closed default.
  viewer,

  /// Can operate the device but not manage pairings.
  member,

  /// Full control, including pairing and revoking other phones.
  owner,
}

/// Wire encoding for [PairingRole].
extension PairingRoleWire on PairingRole {
  /// The role's name on the wire.
  String get wire => name;

  /// Parses a wire value. Anything unknown or missing maps to
  /// [PairingRole.viewer]: an unrecognised role gets least privilege.
  static PairingRole fromWire(String? s) => switch (s) {
        'owner' => PairingRole.owner,
        'member' => PairingRole.member,
        _ => PairingRole.viewer, // fail closed
      };
}

/// A credential issued by the device at pairing.
///
/// Everything outside this class should reference [credentialId], never the
/// secret, so the credential type (bearer token today, a client certificate
/// later) can change without touching logs, state or revocation lists.
class PairingCredential {
  /// Opaque identifier for this credential. Safe to log.
  final String credentialId;

  /// Identifier of the device that issued the credential.
  final String deviceId;

  /// Host the device is reachable at.
  final String host;

  /// Optional fingerprint of the device's TLS certificate, for pinning.
  final String? certFingerprint;

  /// Role granted by the device.
  final PairingRole role;

  /// How the phone authenticates with this credential (`bearer` today; a
  /// future value such as `mtls` lets both sides support a transition).
  final String authMethod;

  /// When the device issued the credential.
  final DateTime issuedAt;

  /// Optional expiry, for session-scoped credentials.
  final DateTime? expiresAt;

  /// The bearer secret. Never logged and never included in [toJsonSafe].
  final String? token;

  /// Creates a credential.
  const PairingCredential({
    required this.credentialId,
    required this.deviceId,
    required this.host,
    this.certFingerprint,
    required this.role,
    this.authMethod = 'bearer',
    required this.issuedAt,
    this.expiresAt,
    this.token,
  });

  /// True once [expiresAt] has passed. Credentials without an expiry never
  /// expire on the client side.
  bool get isExpired => expiresAt != null && DateTime.now().isAfter(expiresAt!);

  /// Representation for logs and diagnostics. Deliberately omits [token].
  Map<String, dynamic> toJsonSafe() => {
        'credential_id': credentialId,
        'device_id': deviceId,
        'host': host,
        'role': role.wire,
        'auth_method': authMethod,
        'issued_at': issuedAt.toIso8601String(),
        'expires_at': expiresAt?.toIso8601String(),
        // token intentionally absent
      };

  /// Full representation including [token], for round-tripping through
  /// secure local storage only. Never log this or send it anywhere else.
  Map<String, dynamic> toStorageJson() => {
        ...toJsonSafe(),
        'cert_fingerprint': certFingerprint,
        'token': token,
      };

  /// Parses the device's pairing response, or a [toStorageJson] blob.
  factory PairingCredential.fromJson(Map<String, dynamic> j) => PairingCredential(
        credentialId: j['credential_id'],
        deviceId: j['device_id'],
        host: j['host'],
        certFingerprint: j['cert_fingerprint'],
        role: PairingRoleWire.fromWire(j['role']),
        authMethod: j['auth_method'] ?? 'bearer',
        issuedAt: DateTime.tryParse(j['issued_at'] ?? '') ?? DateTime.now(),
        expiresAt: j['expires_at'] != null ? DateTime.tryParse(j['expires_at']) : null,
        token: j['token'],
      );
}
