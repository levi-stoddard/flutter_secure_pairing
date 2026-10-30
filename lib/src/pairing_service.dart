// The pairing flow: make sure a device key exists, send only its public half
// to the device, and persist the credential the device issues.
//
// Root of trust is physical access to the device. A credential is only
// issued while the device has a pairing window open, which should require a
// physical button press on the unit or an already-paired owner opening one.

import 'package:flutter/foundation.dart';

import 'credential.dart';
import 'credential_store.dart';
import 'key_material.dart';
import 'pairing_target.dart';
import 'pairing_transport.dart';

/// The request a phone sends to a device to ask for a credential.
///
/// Example wire format (invented for this package):
///
/// ```json
/// {
///   "device_id": "dev-0001",
///   "display_name": "Pat's phone",
///   "public_key": "-----BEGIN PUBLIC KEY-----\n...",
///   "auth_method": "bearer",
///   "client_version": "0.1.0"
/// }
/// ```
class PairingRequest {
  /// Identifier of the device being paired with.
  final String deviceId;

  /// Human-readable name for this phone, shown in the device's paired list.
  final String displayName;

  /// This phone's public key (PEM). Never the private key.
  final String publicKeyPem;

  /// Authentication method the phone will use with the issued credential.
  /// Sending it from day one lets a device support more than one method
  /// during a transition, and lets an old client fail cleanly.
  final String authMethod;

  /// Version of the client sending the request.
  final String clientVersion;

  /// Creates a request.
  const PairingRequest({
    required this.deviceId,
    required this.displayName,
    required this.publicKeyPem,
    this.authMethod = 'bearer',
    this.clientVersion = '0.1.0',
  });

  /// The request body.
  Map<String, dynamic> toJson() => {
        'device_id': deviceId,
        'display_name': displayName,
        'public_key': publicKeyPem,
        'auth_method': authMethod,
        'client_version': clientVersion,
      };
}

/// Runs the pairing flow and exposes the current pairing state.
class PairingService extends ChangeNotifier {
  /// The device keypair.
  final KeyMaterial keyMaterial;

  /// Where the issued credential is persisted.
  final CredentialStore store;

  /// How the pairing request reaches the device.
  final PairingTransport transport;

  /// Version string sent in every [PairingRequest].
  final String clientVersion;

  /// The current credential, if paired.
  PairingCredential? credential;

  /// True while a pairing request is in flight.
  bool busy = false;

  /// Creates a service. [keyMaterial] and [store] default to the secure,
  /// platform-storage-backed implementations.
  PairingService({
    required this.transport,
    KeyMaterial? keyMaterial,
    CredentialStore? store,
    this.clientVersion = '0.1.0',
  })  : keyMaterial = keyMaterial ?? SecureKeyMaterial(),
        store = store ?? SecureCredentialStore();

  /// The current role. Fails closed: unpaired or expired means viewer.
  PairingRole get role => isPaired ? credential!.role : PairingRole.viewer;

  /// True when a credential is held and has not expired.
  bool get isPaired => credential != null && !credential!.isExpired;

  /// Loads any previously stored credential.
  Future<void> restore() async {
    credential = await store.load();
    notifyListeners();
  }

  /// Asks [target] for a credential.
  ///
  /// The keypair is created (or restored) first, and only its public key is
  /// sent. The credential is persisted only on [PairingOutcome.success].
  Future<PairingResult> pair(PairingTarget target, {String? displayName}) async {
    busy = true;
    notifyListeners();
    try {
      await keyMaterial.ensureKeypair();
      final pub = await keyMaterial.publicKeyPem();

      final request = PairingRequest(
        deviceId: target.deviceId,
        displayName: displayName ?? 'Phone',
        publicKeyPem: pub,
        clientVersion: clientVersion,
      ).toJson();

      final result = await transport.pair(target, request);
      if (result.outcome == PairingOutcome.success && result.credential != null) {
        credential = result.credential;
        await store.save(result.credential!);
      }
      return result;
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  /// Forgets the credential locally. Revoking it on the device is a separate,
  /// device-side operation.
  Future<void> unpair() async {
    credential = null;
    await store.clear();
    notifyListeners();
  }
}
