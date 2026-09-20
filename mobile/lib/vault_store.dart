import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';
import 'package:uuid/uuid.dart';
import 'vault_crypto.dart';

class ApiFailure implements Exception {
  final int status;
  final String message;
  ApiFailure(this.status, this.message);
  @override
  String toString() => message;
}

class VaultStore extends ChangeNotifier {
  static const apiUrl = String.fromEnvironment(
    'API_URL',
    defaultValue: 'http://10.0.2.2:8000',
  );
  final storage = const FlutterSecureStorage(
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.unlocked_this_device,
    ),
  );
  final biometricStorage = const FlutterSecureStorage(
    aOptions: AndroidOptions.biometric(
      enforceBiometrics: true,
      storageNamespace: 'vaultpass_biometric',
    ),
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.unlocked_this_device,
    ),
  );
  String access = '', refresh = '', userId = '', vaultId = '', email = '';
  Uint8List? accountKey, vaultKey;
  Map<String, dynamic> bundle = {}, wrappedVault = {};
  List<Map<String, dynamic>> rows = [], pending = [], items = [];
  bool loading = false;
  int generation = 0;
  bool get unlocked => vaultKey != null;
  Future<File> get cache async => File(
    '${(await getApplicationSupportDirectory()).path}/vaultpass-cache.json',
  );
  Future<dynamic> request(
    String path, {
    String method = 'GET',
    Object? body,
    bool retry = true,
  }) async {
    final uri = Uri.parse('$apiUrl$path');
    if (kReleaseMode && uri.scheme != 'https') {
      throw StateError('Release builds require an HTTPS API_URL');
    }
    final response = http.Request(method, uri)
      ..headers.addAll({
        'Content-Type': 'application/json',
        if (access.isNotEmpty) 'Authorization': 'Bearer $access',
      });
    if (body != null) response.body = jsonEncode(body);
    final result = await http.Response.fromStream(
      await response.send().timeout(const Duration(seconds: 20)),
    );
    if (result.statusCode == 401 &&
        refresh.isNotEmpty &&
        retry &&
        !path.startsWith('/auth/')) {
      final renewed =
          await request(
                '/auth/refresh',
                method: 'POST',
                body: {'token': refresh},
                retry: false,
              )
              as Map<String, dynamic>;
      access = renewed['access_token'];
      refresh = renewed['refresh_token'];
      await storage.write(key: 'refresh', value: refresh);
      return request(path, method: method, body: body, retry: false);
    }
    if (result.statusCode >= 400) {
      throw ApiFailure(
        result.statusCode,
        (jsonDecode(result.body) as Map)['detail'].toString(),
      );
    }
    return jsonDecode(result.body);
  }

  Future<void> login(
    String address,
    String master, {
    bool register = false,
  }) async {
    final epoch = generation;
    dynamic result;
    if (register) {
      if (master.length < 12) throw ArgumentError('Use at least 12 characters');
      final id = const Uuid().v4(),
          vid = const Uuid().v4(),
          salt = hex(randomBytes(16)),
          d = await derive(master, salt);
      final ak = randomBytes(32), vk = randomBytes(32);
      try {
        result = await request(
          '/auth/register',
          method: 'POST',
          body: {
            'id': id,
            'email': address,
            'auth_secret': d.auth,
            'bundle': {
              'salt': salt,
              'profile': profile,
              'account_key': await seal(d.wrap, ak, aad('account', [id])),
            },
            'vault_id': vid,
            'wrapped_vault_key': await seal(ak, vk, aad('vault', [id, vid])),
            'device': Platform.isAndroid ? 'Android' : 'iOS',
          },
        );
      } finally {
        d.wrap.fillRange(0, 32, 0);
        ak.fillRange(0, 32, 0);
        vk.fillRange(0, 32, 0);
      }
    } else {
      final lookup = await request(
        '/auth/lookup',
        method: 'POST',
        body: {'email': address},
      );
      if (lookup['profile'] != profile) {
        throw StateError('Unsupported key derivation profile');
      }
      final d = await derive(master, lookup['salt']);
      try {
        result = await request(
          '/auth/login',
          method: 'POST',
          body: {
            'email': address,
            'auth_secret': d.auth,
            'device': Platform.isAndroid ? 'Android' : 'iOS',
          },
        );
      } finally {
        d.wrap.fillRange(0, 32, 0);
      }
    }
    if (epoch != generation) throw StateError('Unlock cancelled');
    access = result['access_token'];
    refresh = result['refresh_token'];
    userId = result['user_id'];
    bundle = Map<String, dynamic>.from(result['bundle']);
    email = address;
    final d = await derive(master, bundle['salt']);
    try {
      accountKey = await open(
        d.wrap,
        Map<String, dynamic>.from(bundle['account_key']),
        aad('account', [userId]),
      );
    } finally {
      d.wrap.fillRange(0, 32, 0);
    }
    final vaults = await request('/vaults') as List;
    vaultId = vaults.first['id'];
    wrappedVault = Map<String, dynamic>.from(vaults.first['wrapped_key']);
    vaultKey = await open(
      accountKey!,
      wrappedVault,
      aad('vault', [userId, vaultId]),
    );
    // Preserve unsent changes only for this same account. Never mix accounts.
    await loadCache(expectedUser: userId);
    await storage.write(key: 'refresh', value: refresh);
    if (epoch != generation) {
      lock();
      throw StateError('Unlock cancelled');
    }
    await synchronize();
    notifyListeners();
  }

  Future<bool> loadCache({String? expectedUser}) async {
    final f = await cache;
    if (!await f.exists()) return false;
    final saved = jsonDecode(await f.readAsString()) as Map<String, dynamic>;
    if (expectedUser != null && saved['user_id'] != expectedUser) {
      rows = [];
      pending = [];
      return false;
    }
    if (expectedUser == null) {
      userId = saved['user_id'];
      vaultId = saved['vault_id'];
      bundle = Map<String, dynamic>.from(saved['bundle']);
      wrappedVault = Map<String, dynamic>.from(saved['wrapped_key']);
      email = saved['email'];
    }
    rows = (saved['rows'] as List)
        .map((e) => Map<String, dynamic>.from(e))
        .toList();
    pending = (saved['pending'] as List)
        .map((e) => Map<String, dynamic>.from(e))
        .toList();
    return true;
  }

  Future<void> persist() async {
    final f = await cache, temporary = File('${(await cache).path}.tmp');
    await temporary.writeAsString(
      jsonEncode({
        'user_id': userId,
        'vault_id': vaultId,
        'email': email,
        'bundle': bundle,
        'wrapped_key': wrappedVault,
        'rows': rows,
        'pending': pending,
      }),
      flush: true,
    );
    await temporary.rename(f.path);
  }

  Future<void> offlineUnlock(String master) async {
    final epoch = generation;
    if (!await loadCache()) {
      throw StateError('Sign in online once to create an encrypted cache');
    }
    if (bundle['profile'] != profile) throw StateError('Unsupported profile');
    final d = await derive(master, bundle['salt']);
    try {
      accountKey = await open(
        d.wrap,
        Map<String, dynamic>.from(bundle['account_key']),
        aad('account', [userId]),
      );
    } finally {
      d.wrap.fillRange(0, 32, 0);
    }
    vaultKey = await open(
      accountKey!,
      wrappedVault,
      aad('vault', [userId, vaultId]),
    );
    refresh = await storage.read(key: 'refresh') ?? '';
    if (epoch != generation) {
      lock();
      throw StateError('Unlock cancelled');
    }
    await decryptRows();
    notifyListeners();
  }

  Future<void> enableBiometric() async {
    if (!Platform.isAndroid) {
      throw StateError(
        'Biometric key binding is currently implemented for Android only',
      );
    }
    if (accountKey == null) {
      throw StateError('Unlock with your master password first');
    }
    await biometricStorage.write(
      key: 'account_key',
      value: jsonEncode({'user_id': userId, 'key': base64Encode(accountKey!)}),
    );
  }

  Future<void> biometricUnlock() async {
    if (!Platform.isAndroid) throw StateError('Available on Android only');
    if (!await loadCache()) throw StateError('No cached vault');
    final secret = await biometricStorage.read(key: 'account_key');
    if (secret == null) throw StateError('Enable biometrics after signing in');
    final value = jsonDecode(secret) as Map;
    if (value['user_id'] != userId) {
      throw StateError('Biometric key belongs to a different account');
    }
    accountKey = base64Decode(value['key']);
    vaultKey = await open(
      accountKey!,
      wrappedVault,
      aad('vault', [userId, vaultId]),
    );
    refresh = await storage.read(key: 'refresh') ?? '';
    await decryptRows();
    notifyListeners();
  }

  Future<void> decryptRows() async {
    final decrypted = <Map<String, dynamic>>[];
    for (final row in rows) {
      if (row['purged'] == true) continue;
      decrypted.add({
        ...row,
        'data': await decryptJson(
          vaultKey!,
          Map<String, dynamic>.from(row['payload']),
          aad('item', [vaultId, row['id'], row['version']]),
        ),
      });
    }
    if (unlocked) {
      items = decrypted;
      notifyListeners();
    }
  }

  Future<void> save(
    Map<String, dynamic> data, {
    Map<String, dynamic>? existing,
    bool deleted = false,
  }) async {
    if (loading) throw StateError('Wait for synchronization to finish');
    final id = existing?['id'] ?? const Uuid().v4();
    final queued = pending.where((p) => p['id'] == id).firstOrNull;
    final expected = queued?['expected_version'] ?? existing?['version'] ?? 0;
    final payload = await encryptJson(
      vaultKey!,
      data,
      aad('item', [vaultId, id, expected + 1]),
    );
    pending.removeWhere((p) => p['id'] == id);
    pending.add({
      'id': id,
      'expected_version': expected,
      'payload': payload,
      'deleted': deleted,
    });
    rows.removeWhere((p) => p['id'] == id);
    rows.add({
      'id': id,
      'version': expected + 1,
      'payload': payload,
      'deleted': deleted,
      'purged': false,
      'updated': DateTime.now().millisecondsSinceEpoch ~/ 1000,
    });
    await persist();
    await decryptRows();
  }

  Future<void> synchronize() async {
    if (loading || !unlocked) return;
    loading = true;
    notifyListeners();
    try {
      if (access.isEmpty) {
        final tokens = await request(
          '/auth/refresh',
          method: 'POST',
          body: {'token': refresh},
        );
        access = tokens['access_token'];
        refresh = tokens['refresh_token'];
        await storage.write(key: 'refresh', value: refresh);
      }
      // A conflict never destroys the local encrypted edit. User can keep it as a copy.
      while (pending.isNotEmpty) {
        final p = pending.first;
        await request(
          '/vaults/$vaultId/items/${p['id']}',
          method: 'PUT',
          body: {
            'expected_version': p['expected_version'],
            'payload': p['payload'],
            'deleted': p['deleted'],
          },
        );
        pending.removeAt(0);
        await persist();
      }
      var cursor = 0, more = true;
      final remote = <Map<String, dynamic>>[];
      while (more) {
        final result = await request('/vaults/$vaultId/sync?after=$cursor');
        remote.addAll(
          (result['items'] as List).map((e) => Map<String, dynamic>.from(e)),
        );
        cursor = result['cursor'];
        more = result['has_more'];
      }
      rows = remote;
      await persist();
      await decryptRows();
    } finally {
      loading = false;
      notifyListeners();
    }
  }

  Future<void> preserveConflictAsCopy() async {
    if (pending.isEmpty) throw StateError('No pending changes');
    final p = pending.first;
    final data = await decryptJson(
      vaultKey!,
      Map<String, dynamic>.from(p['payload']),
      aad('item', [vaultId, p['id'], p['expected_version'] + 1]),
    );
    data['title'] = '${data['title']} (conflict copy)';
    // Persist the replacement before dropping the old pending write.
    await save(data);
    pending.remove(p);
    await persist();
    await synchronize();
  }

  void lock() {
    generation++;
    accountKey?.fillRange(0, accountKey!.length, 0);
    vaultKey?.fillRange(0, vaultKey!.length, 0);
    accountKey = null;
    vaultKey = null;
    items = [];
    access = '';
    refresh = '';
    notifyListeners();
  }

  Future<void> logout() async {
    if (pending.isNotEmpty) {
      throw StateError('Synchronize pending edits before signing out');
    }
    try {
      await request('/auth/logout', method: 'POST');
    } finally {
      await storage.deleteAll();
      await biometricStorage.deleteAll();
      final f = await cache;
      if (await f.exists()) await f.delete();
      lock();
    }
  }
}
