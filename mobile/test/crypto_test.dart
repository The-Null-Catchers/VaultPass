import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:vaultpass/vault_crypto.dart';

void main() {
  test('Cross-client Argon2id/HKDF public interoperability vector', () async {
    final d = await derive(
      'PUBLIC INTEROP TEST PASSWORD',
      '000102030405060708090a0b0c0d0e0f',
    );
    expect(
      hex(d.wrap),
      '6bbb2ee916608f4432679046375df675c3634f326860d2b4a61eef924596cc2c',
    );
    expect(
      d.auth,
      '0b06dd11a65c05b07997387d3259214daa8f3c5d4404721605dd9ba402ab72d8',
    );
  });
  test('AES-GCM round trip, tampering, wrong key and context', () async {
    final key = randomBytes(32), plain = utf8.encode('fake test secret');
    final envelope = await seal(key, plain, 'test:1');
    expect(await open(key, envelope, 'test:1'), plain);
    await expectLater(
      open(randomBytes(32), envelope, 'test:1'),
      throwsA(anything),
    );
    await expectLater(open(key, envelope, 'test:2'), throwsA(anything));
    final damaged = base64Decode(envelope['ciphertext'] as String);
    damaged[0] ^= 1;
    await expectLater(
      open(key, {...envelope, 'ciphertext': base64Encode(damaged)}, 'test:1'),
      throwsA(anything),
    );
  });
  test(
    'Account rewrap preserves the account key under a new password',
    () async {
      final accountKey = randomBytes(32);
      final update = await rewrapAccount(
        'PUBLIC NEW MASTER PASSWORD',
        '00000000-0000-0000-0000-000000000001',
        accountKey,
      );
      final derived = await derive(
        'PUBLIC NEW MASTER PASSWORD',
        update.bundle['salt'] as String,
      );
      try {
        final opened = await open(
          derived.wrap,
          Map<String, dynamic>.from(update.bundle['account_key'] as Map),
          aad('account', ['00000000-0000-0000-0000-000000000001']),
        );
        expect(opened, accountKey);
        opened.fillRange(0, opened.length, 0);
      } finally {
        derived.wrap.fillRange(0, derived.wrap.length, 0);
        accountKey.fillRange(0, accountKey.length, 0);
      }
    },
  );

  test(
    'Recovery key wraps account key and rejects the wrong context',
    () async {
      final accountKey = randomBytes(32);
      final recovery = await createRecovery(
        accountKey,
        'public-recovery-context',
      );
      final opened = await unlockRecovery(
        recovery.recoveryKey,
        'public-recovery-context',
        recovery.accountKey,
      );
      try {
        expect(opened.accountKey, accountKey);
        expect(opened.recoveryAuth, recovery.recoveryAuth);
        await expectLater(
          unlockRecovery(
            recovery.recoveryKey,
            'wrong-context',
            recovery.accountKey,
          ),
          throwsA(anything),
        );
      } finally {
        opened.accountKey.fillRange(0, opened.accountKey.length, 0);
        accountKey.fillRange(0, accountKey.length, 0);
      }
    },
  );

  test('RFC6238 vector', () async {
    expect(
      await totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', seconds: 59, digits: 8),
      '94287082',
    );
  });
  test('Password generator categories and limits', () {
    final p = generatePassword();
    expect(p.length, 24);
    expect(RegExp(r'[A-Z]').hasMatch(p), true);
    expect(RegExp(r'[a-z]').hasMatch(p), true);
    expect(RegExp(r'[0-9]').hasMatch(p), true);
    expect(() => generatePassword(4), throwsArgumentError);
  });
}
