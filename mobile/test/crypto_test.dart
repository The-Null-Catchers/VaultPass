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
