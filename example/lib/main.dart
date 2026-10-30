// Minimal flutter_secure_pairing demo: generate the device key, show its
// fingerprint, and run a simulated pairing against FakePairingTransport.
// No network connection is made.

import 'package:flutter/material.dart';
import 'package:flutter_secure_pairing/flutter_secure_pairing.dart';

void main() => runApp(const ExampleApp());

/// Root widget.
class ExampleApp extends StatelessWidget {
  /// Creates the app.
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'flutter_secure_pairing',
      theme: ThemeData(colorSchemeSeed: Colors.teal, useMaterial3: true),
      home: const PairingDemoPage(),
    );
  }
}

/// The single demo screen.
class PairingDemoPage extends StatefulWidget {
  /// Creates the page.
  const PairingDemoPage({super.key});

  @override
  State<PairingDemoPage> createState() => _PairingDemoPageState();
}

class _PairingDemoPageState extends State<PairingDemoPage> {
  // The QR payload a device would print on its label. It contains no secret.
  static const _sampleQr = 'securepair://pair?d=demo-device-01&h=device.local';

  final _keys = SecureKeyMaterial();
  late final PairingService _pairing = PairingService(
    keyMaterial: _keys,
    transport: FakePairingTransport.unclaimedDevice(
      latency: const Duration(milliseconds: 600),
    ),
  );
  final _qr = TextEditingController(text: _sampleQr);

  String? _fingerprint;
  String? _status;

  @override
  void initState() {
    super.initState();
    _pairing.addListener(_onChange);
    _pairing.restore();
  }

  @override
  void dispose() {
    _pairing.removeListener(_onChange);
    _pairing.dispose();
    _qr.dispose();
    super.dispose();
  }

  void _onChange() => setState(() {});

  Future<void> _generateKey() async {
    await _keys.ensureKeypair();
    final fp = await _keys.publicKeyFingerprint();
    setState(() => _fingerprint = fp);
  }

  Future<void> _pair() async {
    final target = PairingTarget.tryParse(_qr.text);
    if (target == null) {
      setState(() => _status = 'Not a valid pairing code.');
      return;
    }
    final result = await _pairing.pair(target, displayName: 'Example phone');
    if (!mounted) return;
    if (result.outcome != PairingOutcome.success) {
      setState(() => _status = 'Pairing failed: ${result.outcome.name}');
      return;
    }
    // Never accept an unclaimed device silently: ask the user.
    if (result.deviceWasUnclaimed) {
      final keep = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('This device had no previous owner'),
          content: const Text(
            'Expected if you just unboxed it. If it should already belong to '
            'someone, stop and check before continuing.',
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Stop')),
            FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Continue')),
          ],
        ),
      );
      if (keep != true) {
        await _pairing.unpair();
        setState(() => _status = 'Pairing cancelled.');
        return;
      }
    }
    await _generateKey();
    setState(() => _status = 'Paired as ${_pairing.role.name}.');
  }

  @override
  Widget build(BuildContext context) {
    final cred = _pairing.credential;
    final mono = Theme.of(context).textTheme.bodySmall?.copyWith(fontFamily: 'monospace');
    return Scaffold(
      appBar: AppBar(title: const Text('Secure pairing demo')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text('1. Device key', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          const Text('A P-256 keypair generated on this phone. The private key stays in secure storage.'),
          const SizedBox(height: 8),
          OutlinedButton(onPressed: _generateKey, child: const Text('Generate / load key')),
          if (_fingerprint != null) ...[
            const SizedBox(height: 8),
            const Text('Public key fingerprint (SHA-256):'),
            SelectableText(_fingerprint!, style: mono),
          ],
          const Divider(height: 32),
          Text('2. Pair (simulated)', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          TextField(
            controller: _qr,
            decoration: const InputDecoration(labelText: 'QR payload', border: OutlineInputBorder()),
          ),
          const SizedBox(height: 8),
          FilledButton(
            onPressed: _pairing.busy ? null : _pair,
            child: Text(_pairing.busy ? 'Pairing…' : 'Pair with fake device'),
          ),
          if (_status != null) ...[const SizedBox(height: 8), Text(_status!)],
          const Divider(height: 32),
          Text('3. Stored credential', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          if (cred == null)
            const Text('Not paired.')
          else ...[
            Text('Log-safe view (no token):', style: Theme.of(context).textTheme.bodySmall),
            SelectableText(cred.toJsonSafe().toString(), style: mono),
            const SizedBox(height: 8),
            OutlinedButton(onPressed: _pairing.unpair, child: const Text('Unpair')),
          ],
        ],
      ),
    );
  }
}
