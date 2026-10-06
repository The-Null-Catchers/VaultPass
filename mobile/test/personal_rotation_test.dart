import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vaultpass/personal_rotation.dart';
import 'package:vaultpass/vault_crypto.dart';

void main() {
  test(
    'rotation stages every next-revision ciphertext and returns new key',
    () async {
      final accountKey = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final candidate = Uint8List.fromList(List<int>.filled(32, 7));
      final calls = <Map<String, dynamic>>[];
      final entries = [
        {
          'id': 'item-1',
          'version': 3,
          'deleted': false,
          'data': {'title': 'Secret'},
        },
      ];

      Future<dynamic> request(
        String path, {
        String method = 'GET',
        Object? body,
      }) async {
        calls.add({'path': path, 'method': method, 'body': body});
        if (path == '/vaults/vault/rotations' && method == 'POST') {
          return {
            'id': 'rotation',
            'expected_key_version': 2,
            'new_key_version': 3,
            'expires': 999,
            'required_items': [
              {'id': 'item-1', 'version': 3, 'deleted': false},
            ],
            'uploaded_items': 0,
            'complete': false,
          };
        }
        if (path.endsWith('/items/item-1')) return {'ok': true};
        if (path == '/vaults/vault/rotations/rotation') {
          return {
            'id': 'rotation',
            'expected_key_version': 2,
            'new_key_version': 3,
            'expires': 999,
            'required_items': [
              {'id': 'item-1', 'version': 3, 'deleted': false},
            ],
            'uploaded_items': 1,
            'complete': true,
          };
        }
        if (path.endsWith('/finalize')) return {'key_version': 3};
        fail('Unexpected request $method $path');
      }

      final result = await rotatePersonalVault(
        userId: 'user',
        vaultId: 'vault',
        currentKeyVersion: 2,
        accountKey: accountKey,
        entries: entries,
        request: request,
        makeKey: () => candidate,
        makeId: () => 'rotation',
      );

      expect(result.keyVersion, 3);
      expect(result.vaultKey, same(candidate));
      final startBody = calls.first['body'] as Map<String, dynamic>;
      expect(startBody['expected_key_version'], 2);
      final stage = calls.firstWhere(
        (call) => (call['path'] as String).endsWith('/items/item-1'),
      );
      final stageBody = stage['body'] as Map<String, dynamic>;
      expect(stageBody['expected_version'], 3);
      final clear = await decryptJson(
        candidate,
        Map<String, dynamic>.from(stageBody['payload'] as Map),
        aad('item', ['vault', 'item-1', 4]),
      );
      expect(clear['title'], 'Secret');
    },
  );

  test('snapshot mismatch cancels staging and wipes candidate', () async {
    final candidate = Uint8List.fromList(List<int>.filled(32, 9));
    var cancelled = false;

    Future<dynamic> request(
      String path, {
      String method = 'GET',
      Object? body,
    }) async {
      if (path == '/vaults/vault/rotations' && method == 'POST') {
        return {
          'new_key_version': 2,
          'required_items': [
            {'id': 'item-1', 'version': 2, 'deleted': false},
          ],
        };
      }
      if (method == 'DELETE') {
        cancelled = true;
        return {'ok': true};
      }
      fail('Unexpected request $method $path');
    }

    await expectLater(
      rotatePersonalVault(
        userId: 'user',
        vaultId: 'vault',
        currentKeyVersion: 1,
        accountKey: Uint8List(32),
        entries: [
          {
            'id': 'item-1',
            'version': 1,
            'deleted': false,
            'data': {'title': 'Local'},
          },
        ],
        request: request,
        makeKey: () => candidate,
        makeId: () => 'rotation',
      ),
      throwsA(isA<StateError>()),
    );
    expect(cancelled, isTrue);
    expect(candidate.every((value) => value == 0), isTrue);
  });

  test(
    'lost finalize response keeps candidate when server epoch advanced',
    () async {
      final candidate = Uint8List.fromList(List<int>.filled(32, 11));
      var finalizeCalled = false;

      Future<dynamic> request(
        String path, {
        String method = 'GET',
        Object? body,
      }) async {
        if (path == '/vaults/vault/rotations' && method == 'POST') {
          return {
            'new_key_version': 2,
            'required_items': <Map<String, dynamic>>[],
          };
        }
        if (path == '/vaults/vault/rotations/rotation') {
          return {
            'new_key_version': 2,
            'required_items': <Map<String, dynamic>>[],
            'uploaded_items': 0,
            'complete': true,
          };
        }
        if (path.endsWith('/finalize')) {
          finalizeCalled = true;
          throw StateError('connection dropped');
        }
        if (path == '/vaults' && finalizeCalled) {
          return [
            {
              'id': 'vault',
              'key_version': 2,
              'wrapped_key': {
                'v': 1,
                'nonce': 'AAAAAAAAAAAAAAAA',
                'ciphertext': 'AAAAAAAAAAAAAAAAAAAAAA==',
              },
            },
          ];
        }
        fail('Unexpected request $method $path');
      }

      final result = await rotatePersonalVault(
        userId: 'user',
        vaultId: 'vault',
        currentKeyVersion: 1,
        accountKey: Uint8List(32),
        entries: const [],
        request: request,
        makeKey: () => candidate,
        makeId: () => 'rotation',
      );

      expect(result.keyVersion, 2);
      expect(candidate.every((value) => value == 11), isTrue);
    },
  );

  test('failed finalize without epoch advance wipes candidate', () async {
    final candidate = Uint8List.fromList(List<int>.filled(32, 13));

    Future<dynamic> request(
      String path, {
      String method = 'GET',
      Object? body,
    }) async {
      if (path == '/vaults/vault/rotations' && method == 'POST') {
        return {
          'new_key_version': 2,
          'required_items': <Map<String, dynamic>>[],
        };
      }
      if (path == '/vaults/vault/rotations/rotation') {
        return {
          'new_key_version': 2,
          'required_items': <Map<String, dynamic>>[],
          'uploaded_items': 0,
          'complete': true,
        };
      }
      if (path.endsWith('/finalize')) throw StateError('server failed');
      if (path == '/vaults') {
        return [
          {'id': 'vault', 'key_version': 1, 'wrapped_key': <String, dynamic>{}},
        ];
      }
      fail('Unexpected request $method $path');
    }

    await expectLater(
      rotatePersonalVault(
        userId: 'user',
        vaultId: 'vault',
        currentKeyVersion: 1,
        accountKey: Uint8List(32),
        entries: const [],
        request: request,
        makeKey: () => candidate,
        makeId: () => 'rotation',
      ),
      throwsA(isA<StateError>()),
    );
    expect(candidate.every((value) => value == 0), isTrue);
  });
}
