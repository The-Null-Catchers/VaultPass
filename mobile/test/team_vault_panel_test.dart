import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:vaultpass/team_vault_panel.dart';
import 'package:vaultpass/vault_store.dart';

void main() {
  test('team cache filename is account scoped', () {
    expect(
      teamCacheFileName('11111111-1111-1111-1111-111111111111'),
      isNot(teamCacheFileName('22222222-2222-2222-2222-222222222222')),
    );
    expect(
      teamCacheFileName('11111111-1111-1111-1111-111111111111'),
      contains('11111111-1111-1111-1111-111111111111'),
    );
  });

  testWidgets('read-only team hides editing controls', (tester) async {
    final store = VaultStore();
    final team = <String, dynamic>{
      'id': '11111111-1111-1111-1111-111111111111',
      'name': 'Readonly Team',
      'owner_id': '22222222-2222-2222-2222-222222222222',
      'role': 'read_only',
      'key_version': 3,
      'wrapped_key': 'ciphertext',
    };
    store.teams = [team];
    store.selectedTeam = team;
    store.teamItems = [
      {
        'id': '33333333-3333-3333-3333-333333333333',
        'version': 2,
        'deleted': false,
        'purged': false,
        'updated': 1,
        'data': {
          'title': 'Shared login',
          'username': 'member@example.com',
          'password': 'secret',
          'notes': '',
        },
      },
    ];

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: SingleChildScrollView(child: TeamVaultPanel(store: store))),
      ),
    );

    expect(find.text('Read-only access'), findsOneWidget);
    expect(find.text('Add encrypted team item'), findsNothing);
    expect(find.text('Shared login'), findsOneWidget);
  });

  testWidgets('editable team exposes encrypted item action', (tester) async {
    final store = VaultStore();
    final team = <String, dynamic>{
      'id': '44444444-4444-4444-4444-444444444444',
      'name': 'Engineering',
      'owner_id': '55555555-5555-5555-5555-555555555555',
      'role': 'member',
      'key_version': 1,
      'wrapped_key': 'ciphertext',
    };
    store.teams = [team];
    store.selectedTeam = team;

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: SingleChildScrollView(child: TeamVaultPanel(store: store))),
      ),
    );

    expect(find.text('Add encrypted team item'), findsOneWidget);
    expect(find.text('Read-only access'), findsNothing);
  });
}
