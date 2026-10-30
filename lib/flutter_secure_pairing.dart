/// On-device EC key generation, secure-storage-backed device identity and a
/// transport-agnostic pairing flow.
///
/// Start with [PairingService]: give it a [PairingTransport] (a
/// [FakePairingTransport] for tests and demos, or your own implementation),
/// parse the device's QR label with [PairingTarget.tryParse], and call
/// [PairingService.pair].
library;

export 'src/credential.dart';
export 'src/credential_store.dart';
export 'src/key_material.dart';
export 'src/pairing_service.dart';
export 'src/pairing_target.dart';
export 'src/pairing_transport.dart';
