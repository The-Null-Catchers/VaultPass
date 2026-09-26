import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart' as asn1;
import 'package:pointycastle/export.dart' as pc;

import 'vault_crypto.dart';

const _hashLength = 32;

Uint8List _sha256(List<int> input) =>
    pc.SHA256Digest().process(Uint8List.fromList(input));

Uint8List _xor(List<int> a, List<int> b) {
  if (a.length != b.length) throw const FormatException('Invalid OAEP mask');
  return Uint8List.fromList([for (var i = 0; i < a.length; i++) a[i] ^ b[i]]);
}

Uint8List _mgf1(List<int> seed, int length) {
  final output = BytesBuilder(copy: false);
  for (var counter = 0; output.length < length; counter++) {
    final c = ByteData(4)..setUint32(0, counter, Endian.big);
    output.add(_sha256([...seed, ...c.buffer.asUint8List()]));
  }
  return Uint8List.fromList(output.takeBytes().sublist(0, length));
}

int _modulusBytes(pc.RSAAsymmetricKey key) =>
    ((key.modulus?.bitLength ?? 0) + 7) ~/ 8;

Uint8List _normalizedRsaBlock(Uint8List value, int size) {
  if (value.length == size) return value;
  if (value.length == size + 1 && value.first == 0) {
    return Uint8List.fromList(value.sublist(1));
  }
  if (value.length > size) throw const FormatException('Invalid RSA block');
  final out = Uint8List(size);
  out.setRange(size - value.length, size, value);
  return out;
}

Uint8List _rsa(
  Uint8List input,
  pc.RSAAsymmetricKey key, {
  required bool encrypt,
}) {
  final size = _modulusBytes(key);
  if (size < 256 || size > 512) {
    throw const FormatException('Unsupported RSA key size');
  }
  final engine = pc.RSAEngine()
    ..init(
      encrypt,
      encrypt
          ? pc.PublicKeyParameter<pc.RSAPublicKey>(key as pc.RSAPublicKey)
          : pc.PrivateKeyParameter<pc.RSAPrivateKey>(key as pc.RSAPrivateKey),
    );
  return _normalizedRsaBlock(engine.process(input), size);
}

Uint8List _oaepEncode(Uint8List message, pc.RSAPublicKey key, Uint8List label) {
  final k = _modulusBytes(key);
  if (message.length > k - 2 * _hashLength - 2) {
    throw const FormatException('RSA-OAEP message is too long');
  }
  final lHash = _sha256(label);
  final ps = Uint8List(k - message.length - 2 * _hashLength - 2);
  final db = Uint8List.fromList([...lHash, ...ps, 1, ...message]);
  final seed = randomBytes(_hashLength);
  final dbMask = _mgf1(seed, k - _hashLength - 1);
  final maskedDb = _xor(db, dbMask);
  final seedMask = _mgf1(maskedDb, _hashLength);
  final maskedSeed = _xor(seed, seedMask);
  seed.fillRange(0, seed.length, 0);
  return Uint8List.fromList([0, ...maskedSeed, ...maskedDb]);
}

Uint8List _oaepDecode(
  Uint8List encoded,
  pc.RSAPrivateKey key,
  Uint8List label,
) {
  final k = _modulusBytes(key);
  if (encoded.length != k || k < 2 * _hashLength + 2) {
    throw const FormatException('Invalid RSA-OAEP block');
  }
  final maskedSeed = encoded.sublist(1, 1 + _hashLength);
  final maskedDb = encoded.sublist(1 + _hashLength);
  final seed = _xor(maskedSeed, _mgf1(maskedDb, _hashLength));
  final db = _xor(maskedDb, _mgf1(seed, k - _hashLength - 1));
  seed.fillRange(0, seed.length, 0);

  final expectedHash = _sha256(label);
  var invalid = encoded.first;
  for (var i = 0; i < _hashLength; i++) {
    invalid |= db[i] ^ expectedHash[i];
  }
  var separator = -1;
  for (var i = _hashLength; i < db.length; i++) {
    final value = db[i];
    if (separator < 0) {
      if (value == 1) {
        separator = i;
      } else if (value != 0) {
        invalid |= 1;
      }
    }
  }
  if (invalid != 0 || separator < 0) {
    throw const FormatException('RSA-OAEP integrity check failed');
  }
  return Uint8List.fromList(db.sublist(separator + 1));
}

pc.RSAPublicKey _publicKey(String encoded) {
  final top =
      asn1.ASN1Parser(Uint8List.fromList(base64Decode(encoded))).nextObject()
          as asn1.ASN1Sequence;
  final bitString = top.elements?[1] as asn1.ASN1BitString?;
  if (bitString?.stringValues == null) {
    throw const FormatException('Invalid SPKI public key');
  }
  final rsa =
      asn1.ASN1Parser(Uint8List.fromList(bitString!.stringValues!)).nextObject()
          as asn1.ASN1Sequence;
  final values = rsa.elements;
  if (values == null || values.length != 2) {
    throw const FormatException('Invalid RSA public key');
  }
  final n = (values[0] as asn1.ASN1Integer).integer;
  final e = (values[1] as asn1.ASN1Integer).integer;
  if (n == null || e == null) {
    throw const FormatException('Invalid RSA public key');
  }
  return pc.RSAPublicKey(n, e);
}

pc.RSAPrivateKey _privateKey(Uint8List encoded) {
  final top = asn1.ASN1Parser(encoded).nextObject() as asn1.ASN1Sequence;
  final octets = top.elements?[2] as asn1.ASN1OctetString?;
  if (octets?.octets == null) {
    throw const FormatException('Invalid PKCS8 key');
  }
  final rsa =
      asn1.ASN1Parser(Uint8List.fromList(octets!.octets!)).nextObject()
          as asn1.ASN1Sequence;
  final values = rsa.elements;
  if (values == null || values.length < 6) {
    throw const FormatException('Invalid RSA private key');
  }
  final n = (values[1] as asn1.ASN1Integer).integer;
  final d = (values[3] as asn1.ASN1Integer).integer;
  final p = (values[4] as asn1.ASN1Integer).integer;
  final q = (values[5] as asn1.ASN1Integer).integer;
  if ([n, d, p, q].any((value) => value == null)) {
    throw const FormatException('Invalid RSA private key');
  }
  return pc.RSAPrivateKey(n!, d!, p, q);
}

Uint8List _teamKeyLabel(String teamId, String userId, int keyVersion) =>
    Uint8List.fromList(
      utf8.encode(aad('team-key', [teamId, userId, keyVersion])),
    );

Future<String> wrapTeamKey(
  Uint8List teamKey,
  String publicKey,
  String teamId,
  String userId,
  int keyVersion,
) async {
  if (teamKey.length != 32 || keyVersion < 1) {
    throw const FormatException('Invalid team key context');
  }
  final key = _publicKey(publicKey);
  final encoded = _oaepEncode(
    teamKey,
    key,
    _teamKeyLabel(teamId, userId, keyVersion),
  );
  return base64Encode(_rsa(encoded, key, encrypt: true));
}

Future<Uint8List> unwrapTeamKey(
  String wrappedKey,
  Uint8List accountKey,
  Map<String, dynamic> privateEnvelope,
  String teamId,
  String userId,
  int keyVersion,
) async {
  final privateBytes = await open(
    accountKey,
    privateEnvelope,
    aad('sharing-private', [userId]),
  );
  try {
    final key = _privateKey(privateBytes);
    final encoded = _rsa(
      Uint8List.fromList(base64Decode(wrappedKey)),
      key,
      encrypt: false,
    );
    final result = _oaepDecode(
      encoded,
      key,
      _teamKeyLabel(teamId, userId, keyVersion),
    );
    if (result.length != 32) {
      result.fillRange(0, result.length, 0);
      throw const FormatException('Invalid team key');
    }
    return result;
  } finally {
    privateBytes.fillRange(0, privateBytes.length, 0);
  }
}

Future<Map<String, dynamic>> encryptTeamItem(
  Uint8List key,
  Map<String, dynamic> value,
  String teamId,
  String itemId,
  int keyVersion,
  int itemVersion,
) => encryptJson(
  key,
  value,
  aad('team-item', [teamId, itemId, keyVersion, itemVersion]),
);

Future<Map<String, dynamic>> decryptTeamItem(
  Uint8List key,
  Map<String, dynamic> envelope,
  String teamId,
  String itemId,
  int keyVersion,
  int itemVersion,
) => decryptJson(
  key,
  envelope,
  aad('team-item', [teamId, itemId, keyVersion, itemVersion]),
);
