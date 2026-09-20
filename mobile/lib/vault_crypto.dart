import 'dart:convert';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:pointycastle/export.dart' as pc;

const profile = 'argon2id-m65536-t3-p4-v1';
Uint8List randomBytes(int size) {
  final r = Random.secure();
  return Uint8List.fromList(List.generate(size, (_) => r.nextInt(256)));
}

String hex(List<int> value) =>
    value.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
Uint8List unhex(String value) => Uint8List.fromList([
  for (var i = 0; i < value.length; i += 2)
    int.parse(value.substring(i, i + 2), radix: 16),
]);
String aad(String kind, List<Object> ids) =>
    ['vaultpass', 'v1', kind, ...ids].join(':');
Uint8List argon(List<String> input) {
  final salt = unhex(input[1]);
  if (salt.length != 16) throw const FormatException('Invalid salt');
  final generator = pc.Argon2BytesGenerator()
    ..init(
      pc.Argon2Parameters(
        pc.Argon2Parameters.ARGON2_id,
        salt,
        desiredKeyLength: 32,
        iterations: 3,
        memory: 65536,
        lanes: 4,
        version: pc.Argon2Parameters.ARGON2_VERSION_13,
      ),
    );
  return generator.process(Uint8List.fromList(utf8.encode(input[0])));
}

Future<({Uint8List wrap, String auth})> derive(
  String master,
  String salt,
) async {
  final root = await compute(argon, [master, salt]);
  Future<Uint8List> sub(String label) async => Uint8List.fromList(
    await (await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey(root),
      nonce: List.filled(32, 0),
      info: utf8.encode('vaultpass:v1:$label'),
    )).extractBytes(),
  );
  try {
    return (wrap: await sub('wrap'), auth: hex(await sub('auth')));
  } finally {
    root.fillRange(0, root.length, 0);
  }
}

Future<Map<String, dynamic>> seal(
  Uint8List key,
  List<int> data,
  String context,
) async {
  if (key.length != 32) throw const FormatException('Invalid key');
  final nonce = randomBytes(12);
  final box = await AesGcm.with256bits().encrypt(
    data,
    secretKey: SecretKey(key),
    nonce: nonce,
    aad: utf8.encode(context),
  );
  return {
    'v': 1,
    'nonce': base64Encode(nonce),
    'ciphertext': base64Encode([...box.cipherText, ...box.mac.bytes]),
  };
}

Future<Uint8List> open(
  Uint8List key,
  Map<String, dynamic> envelope,
  String context,
) async {
  final nonce = base64Decode(envelope['nonce'] as String),
      data = base64Decode(envelope['ciphertext'] as String);
  if (envelope['v'] != 1 ||
      nonce.length != 12 ||
      data.length < 16 ||
      key.length != 32) {
    throw const FormatException('Invalid envelope');
  }
  final box = SecretBox(
    data.sublist(0, data.length - 16),
    nonce: nonce,
    mac: Mac(data.sublist(data.length - 16)),
  );
  return Uint8List.fromList(
    await AesGcm.with256bits().decrypt(
      box,
      secretKey: SecretKey(key),
      aad: utf8.encode(context),
    ),
  );
}

Future<Map<String, dynamic>> encryptJson(
  Uint8List key,
  Object data,
  String context,
) => seal(key, utf8.encode(jsonEncode(data)), context);
Future<Map<String, dynamic>> decryptJson(
  Uint8List key,
  Map<String, dynamic> data,
  String context,
) async {
  final plain = await open(key, data, context);
  try {
    return jsonDecode(utf8.decode(plain)) as Map<String, dynamic>;
  } finally {
    plain.fillRange(0, plain.length, 0);
  }
}

String generatePassword([int length = 24]) {
  if (length < 12 || length > 128) throw ArgumentError('Use 12–128 characters');
  const groups = [
    'abcdefghjkmnpqrstuvwxyz',
    'ABCDEFGHJKLMNPQRSTUVWXYZ',
    '23456789',
    '!@#%&*()-_=+?',
  ];
  final alphabet = groups.join(), r = Random.secure();
  String password;
  do {
    password = List.generate(
      length,
      (_) => alphabet[r.nextInt(alphabet.length)],
    ).join();
  } while (!groups.every((g) => g.split('').any(password.contains)));
  return password;
}

Future<String> totp(String seed, {int? seconds, int digits = 6}) async {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  int value = 0, bits = 0;
  final key = <int>[];
  for (final c
      in seed.toUpperCase().replaceAll(RegExp(r'[=\s]'), '').split('')) {
    final n = alphabet.indexOf(c);
    if (n < 0) throw const FormatException('Invalid TOTP seed');
    value = (value << 5) | n;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      key.add((value >> bits) & 255);
    }
  }
  if (key.isEmpty) throw const FormatException('Empty TOTP seed');
  final counter = ByteData(8)
    ..setUint64(
      0,
      (seconds ?? DateTime.now().millisecondsSinceEpoch ~/ 1000) ~/ 30,
    );
  final mac = await Hmac.sha1().calculateMac(
    counter.buffer.asUint8List(),
    secretKey: SecretKey(key),
  );
  final offset = mac.bytes.last & 15;
  final code =
      ((mac.bytes[offset] & 127) << 24) |
      (mac.bytes[offset + 1] << 16) |
      (mac.bytes[offset + 2] << 8) |
      mac.bytes[offset + 3];
  return (code % pow(10, digits).toInt()).toString().padLeft(digits, '0');
}
