import 'dart:typed_data';

import 'package:uuid/uuid.dart';

import 'vault_crypto.dart';

typedef RotationRequest = Future<dynamic> Function(
  String path, {
  String method,
  Object? body,
});

typedef KeyFactory = Uint8List Function();
typedef IdFactory = String Function();

class PersonalRotationResult {
  final Uint8List vaultKey;
  final int keyVersion;
  final Map<String, dynamic> wrappedKey;

  PersonalRotationResult({
    required this.vaultKey,
    required this.keyVersion,
    required this.wrappedKey,
  });
}

Map<String, Map<String, dynamic>> _assertSnapshot(
  List<dynamic> required,
  List<Map<String, dynamic>> entries,
) {
  final byId = <String, Map<String, dynamic>>{
    for (final entry in entries) entry['id'] as String: entry,
  };
  if (required.length != entries.length) {
    throw StateError('Vault changed while preparing key rotation. Sync and try again.');
  }
  for (final raw in required) {
    final row = Map<String, dynamic>.from(raw as Map);
    final entry = byId[row['id']];
    if (entry == null ||
        entry['version'] != row['version'] ||
        (entry['deleted'] == true) != (row['deleted'] == true)) {
      throw StateError('Vault changed while preparing key rotation. Sync and try again.');
    }
  }
  return byId;
}

Future<void> _bestEffortCancel(
  RotationRequest request,
  String vaultId,
  String rotationId,
) async {
  try {
    await request(
      '/vaults/$vaultId/rotations/$rotationId',
      method: 'DELETE',
    );
  } catch (_) {
    // Staging expiry/cancellation must never mutate the active vault key.
  }
}

Future<PersonalRotationResult> rotatePersonalVault({
  required String userId,
  required String vaultId,
  required int currentKeyVersion,
  required Uint8List accountKey,
  required List<Map<String, dynamic>> entries,
  required RotationRequest request,
  KeyFactory? makeKey,
  IdFactory? makeId,
}) async {
  final candidate = (makeKey ?? () => randomBytes(32))();
  if (candidate.length != 32) {
    throw ArgumentError('Personal vault keys must be 256 bits');
  }

  final rotationId = (makeId ?? () => const Uuid().v4())();
  var started = false;
  var finalizeAttempted = false;
  try {
    final wrappedKey = await seal(
      accountKey,
      candidate,
      aad('vault', [userId, vaultId]),
    );
    final start = Map<String, dynamic>.from(
      await request(
            '/vaults/$vaultId/rotations',
            method: 'POST',
            body: {
              'id': rotationId,
              'expected_key_version': currentKeyVersion,
              'wrapped_key': wrappedKey,
            },
          )
          as Map,
    );
    started = true;
    if (start['new_key_version'] != currentKeyVersion + 1) {
      throw StateError('Unexpected vault key epoch from server');
    }

    final required = start['required_items'] as List;
    final byId = _assertSnapshot(required, entries);
    for (final raw in required) {
      final row = Map<String, dynamic>.from(raw as Map);
      final id = row['id'] as String;
      final version = row['version'] as int;
      final entry = byId[id]!;
      final payload = await encryptJson(
        candidate,
        entry['data'] as Map<String, dynamic>,
        aad('item', [vaultId, id, version + 1]),
      );
      await request(
        '/vaults/$vaultId/rotations/$rotationId/items/$id',
        method: 'PUT',
        body: {'expected_version': version, 'payload': payload},
      );
    }

    final progress = Map<String, dynamic>.from(
      await request('/vaults/$vaultId/rotations/$rotationId') as Map,
    );
    final progressRequired = progress['required_items'] as List;
    if (progress['complete'] != true ||
        progress['new_key_version'] != start['new_key_version'] ||
        progress['uploaded_items'] != progressRequired.length) {
      throw StateError('Personal vault key rotation is not ready to finalize');
    }

    finalizeAttempted = true;
    final finalized = Map<String, dynamic>.from(
      await request(
            '/vaults/$vaultId/rotations/$rotationId/finalize',
            method: 'POST',
          )
          as Map,
    );
    return PersonalRotationResult(
      vaultKey: candidate,
      keyVersion: finalized['key_version'] as int,
      wrappedKey: wrappedKey,
    );
  } catch (error) {
    if (finalizeAttempted) {
      try {
        final vaults = await request('/vaults') as List;
        final current = vaults
            .map((row) => Map<String, dynamic>.from(row as Map))
            .where((row) => row['id'] == vaultId)
            .firstOrNull;
        if (current != null && current['key_version'] == currentKeyVersion + 1) {
          return PersonalRotationResult(
            vaultKey: candidate,
            keyVersion: current['key_version'] as int,
            wrappedKey: Map<String, dynamic>.from(current['wrapped_key'] as Map),
          );
        }
      } catch (_) {
        // A later online unlock can recover the committed wrapped key if needed.
      }
    }
    if (started && !finalizeAttempted) {
      await _bestEffortCancel(request, vaultId, rotationId);
    }
    candidate.fillRange(0, candidate.length, 0);
    rethrow;
  }
}
