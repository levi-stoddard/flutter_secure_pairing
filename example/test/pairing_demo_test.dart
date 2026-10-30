import 'package:flutter_secure_pairing_example/main.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));

  testWidgets('simulated pairing shows the unclaimed warning, then pairs as owner', (tester) async {
    await tester.pumpWidget(const ExampleApp());
    await tester.pumpAndSettle();
    expect(find.text('Not paired.'), findsOneWidget);

    await tester.runAsync(() async {
      await tester.tap(find.text('Pair with fake device'));
      await Future<void>.delayed(const Duration(seconds: 1));
    });
    await tester.pumpAndSettle();
    expect(find.text('This device had no previous owner'), findsOneWidget);

    await tester.runAsync(() async {
      await tester.tap(find.text('Continue'));
      await Future<void>.delayed(const Duration(milliseconds: 500));
    });
    await tester.pumpAndSettle();
    expect(find.text('Paired as owner.'), findsOneWidget);
    expect(find.textContaining('Public key fingerprint'), findsOneWidget);
  });
}
