import 'package:flutter_test/flutter_test.dart';
import 'package:vaultpass/main.dart';

void main() {
  testWidgets('Locked vault never renders secret content', (tester) async {
    await tester.pumpWidget(const VaultPassApp());
    expect(find.text('VaultPass'), findsOneWidget);
    expect(find.text('Unlock online'), findsOneWidget);
    expect(find.text('All items'), findsNothing);
  });
}
