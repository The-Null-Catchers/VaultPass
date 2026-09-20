import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:vaultpass/vault_crypto.dart';
import 'package:vaultpass/vault_store.dart';

class OfflineStore extends VaultStore {
  final File file;
  OfflineStore(this.file);
  @override
  Future<File> get cache async => file;
  @override
  Future<dynamic> request(
    String path, {
    String method = 'GET',
    Object? body,
    bool retry = true,
  }) async {
    throw ApiFailure(409, 'Revision conflict');
  }
}

void main() {
  test(
    'Offline edits are encrypted and coalesce without losing their base revision',
    () async {
      final dir = await Directory.systemTemp.createTemp('vaultpass-test-');
      final store = OfflineStore(File('${dir.path}/cache.json'));
      try {
        store.vaultKey = randomBytes(32);
        store.vaultId = 'test-vault';
        store.userId = 'test-user';
        store.access = 'fake-test-access';
        await store.save({
          'title': 'NEVER STORE THIS PLAINTEXT',
          'type': 'note',
          'notes': 'PRIVATE FAKE NOTE',
        });
        expect(store.pending.length, 1);
        expect(
          await store.file.readAsString(),
          isNot(contains('PRIVATE FAKE NOTE')),
        );
        final row = store.items.single;
        await store.save({
          'title': 'changed',
          'type': 'note',
          'notes': 'PRIVATE FAKE NOTE',
        }, existing: row);
        expect(store.pending.length, 1);
        expect(store.pending.single['expected_version'], 0);
        await expectLater(store.synchronize(), throwsA(isA<ApiFailure>()));
        expect(store.pending.length, 1);
        final key = store.vaultKey!;
        store.lock();
        expect(store.items, isEmpty);
        expect(key.every((b) => b == 0), true);
      } finally {
        store.dispose();
        await dir.delete(recursive: true);
      }
    },
  );
}
