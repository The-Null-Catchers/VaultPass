import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vaultpass/security_notifications_tile.dart';
import 'package:vaultpass/vault_store.dart';

class FakeVaultStore extends VaultStore {
  bool value = true;
  bool failPatch = false;
  bool rotated = false;
  final calls = <Map<String, dynamic>>[];

  @override
  Future<dynamic> request(
    String path, {
    String method = 'GET',
    Object? body,
    bool retry = true,
  }) async {
    calls.add({'path': path, 'method': method, 'body': body});
    if (method == 'PATCH') {
      if (failPatch) throw ApiFailure(500, 'save failed');
      final payload = body as Map<String, dynamic>;
      value = payload['new_device_email_enabled'] == true;
    }
    return {'new_device_email_enabled': value};
  }

  @override
  Future<int> rotatePersonalVaultKey() async {
    rotated = true;
    keyVersion = 2;
    return keyVersion;
  }
}

Widget subject(FakeVaultStore store) {
  return MaterialApp(
    home: Scaffold(body: SecurityNotificationsTile(store: store)),
  );
}

void main() {
  const switchKey = ValueKey('new-device-email-switch');

  testWidgets('loads and updates the authenticated preference', (tester) async {
    final store = FakeVaultStore();
    await tester.pumpWidget(subject(store));
    await tester.pumpAndSettle();

    final switchFinder = find.byKey(switchKey);
    expect(switchFinder, findsOneWidget);
    expect(tester.widget<SwitchListTile>(switchFinder).value, isTrue);
    expect(store.calls.first['path'], '/account/security-notifications');
    expect(store.calls.first['method'], 'GET');

    await tester.tap(switchFinder);
    await tester.pumpAndSettle();

    expect(tester.widget<SwitchListTile>(switchFinder).value, isFalse);
    expect(store.calls.last['method'], 'PATCH');
    expect(store.calls.last['body'], {'new_device_email_enabled': false});
  });

  testWidgets('rolls back the switch when saving fails', (tester) async {
    final store = FakeVaultStore()..failPatch = true;
    await tester.pumpWidget(subject(store));
    await tester.pumpAndSettle();

    final switchFinder = find.byKey(switchKey);
    await tester.tap(switchFinder);
    await tester.pumpAndSettle();

    expect(tester.widget<SwitchListTile>(switchFinder).value, isTrue);
    expect(find.textContaining('Could not save preference'), findsOneWidget);
  });

  testWidgets('confirms and runs personal vault key rotation', (tester) async {
    final store = FakeVaultStore();
    await tester.pumpWidget(subject(store));
    await tester.pumpAndSettle();

    await tester.tap(find.byKey(const ValueKey('personal-vault-key-rotation')));
    await tester.pumpAndSettle();
    expect(find.text('Rotate vault encryption key?'), findsOneWidget);

    await tester.tap(find.text('Rotate key'));
    await tester.pumpAndSettle();

    expect(store.rotated, isTrue);
    expect(find.textContaining('rotated to epoch 2'), findsOneWidget);
  });
}
