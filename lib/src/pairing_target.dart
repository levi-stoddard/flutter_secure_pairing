// The pairing QR payload.
//
// Example format (invented for this package; adapt it to your device):
//
//   securepair://pair?d=<device_id>&h=<host>&f=<cert_fingerprint>
//
// The payload deliberately contains NO CREDENTIAL. Photographing the label on
// someone's device must grant nothing: the device also has to have a pairing
// window open (for example, after a physical button press) before it will
// issue a credential.

/// The device a phone wants to pair with, as read from its QR label.
class PairingTarget {
  /// URI scheme used by [tryParse] and [toUri] unless another is given.
  static const defaultScheme = 'securepair';

  /// Identifier of the device.
  final String deviceId;

  /// Host the device is reachable at on the local network.
  final String host;

  /// Optional fingerprint of the device's TLS certificate, for pinning.
  final String? certFingerprint;

  /// Creates a pairing target.
  const PairingTarget({
    required this.deviceId,
    required this.host,
    this.certFingerprint,
  });

  /// Parses a QR payload. Returns null for anything that isn't a well-formed
  /// `<scheme>://pair` URI with a non-empty `d` (device id) and `h` (host).
  static PairingTarget? tryParse(String raw, {String scheme = defaultScheme}) {
    final uri = Uri.tryParse(raw.trim());
    if (uri == null) return null;
    if (uri.scheme != scheme || uri.host != 'pair') return null;
    final d = uri.queryParameters['d'];
    final h = uri.queryParameters['h'];
    if (d == null || d.isEmpty || h == null || h.isEmpty) return null;
    return PairingTarget(
      deviceId: d,
      host: h,
      certFingerprint: uri.queryParameters['f'],
    );
  }

  /// Encodes this target as a QR payload that [tryParse] accepts.
  Uri toUri({String scheme = defaultScheme}) => Uri(
        scheme: scheme,
        host: 'pair',
        queryParameters: {
          'd': deviceId,
          'h': host,
          if (certFingerprint != null) 'f': certFingerprint!,
        },
      );
}
