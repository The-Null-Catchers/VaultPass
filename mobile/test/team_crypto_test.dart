import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:vaultpass/team_crypto.dart';
import 'package:vaultpass/vault_crypto.dart';

void main() {
  const teamId = '11111111-1111-1111-1111-111111111111';
  const userId = '22222222-2222-2222-2222-222222222222';
  const publicKey =
      'MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtUrTPjyD5EDlK2qQAuuKJCI+0TF3p3ZtmWIaaxdSps02wV9ajRAnzvLatCEoR9eBZW331gmuagKBxvncjMLngfJi/cz8ptFFqqWcp3fNSYt66+aIHqQLeVi2lEVPWe+aegx2mToBMAEInioAmJjwjfnDJc7A/ntCZhYy+Bpuwmu5Ve9btj52GICdmtGfA+q84uoj9ErNmbJHTiwcgVDawCe5i9TAYKYiOrBmgiWx86mVtkCBSfrmKl1SXGiOYfU4UQEEuxHh4ke5yfvfzANNc9r03MedmUktAxm6ceXuV1zEyTli8hNItxJIAhU24iyH8Xaf8xxTtziTWZa7caIeyBpXMX0+Ryi9tL1CjOAnPC+mafX2li73XkLPNPN069IZ8ljwJNgFrji6hGIkLa/TP8e1TAIHJ3QIqktjtVVjIJ7ETdYtK/RGCC4Bm4h/1Pv2wBSTJs9SVAbemI5GHWnQAuELi5y6xFw/Bd6CO0zlvH1uSRqqNTFrnlVV03JQe1fJAgMBAAE=';
  const privateKey =
      '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';
  const wrapped =
      'M5kpQ0ux0W4MhluuBckjMrJBtoA2tjc+oqLHprnLBxDPwfLqWWKePP053raEqdPhFXUn5HEjUfchQZaDnGf78976mCbiP60PEsyDv1wSETSuD0YR9I6pmTrK2XplqxG/abvesKAEm5XF0hSZzVG9OJb7fsE4ZnZVUnqnYyKLsXsNOZDtKbAGwZ7bhdx/7wxzWOZQSGB9CW70emtkNfvqa+yk5Q24UEYHHwFWonGgU4axA2O0CASDaxCxcyVHB8QoejItRws4hwdHsuA4X/OaiJBC7MyDSB1QkmiJ/U9fi45+KmcA8H2qPxpAc2lBm4ZXe61cguH1Mc8ftU6ct4Axkrp/T5iKXGjuRDJruZhlYwU/TKUEkGw/j9kBKz7sOogQYCSwT1jTY4CMA1ZBhNGInUt+5/oQLl8v8aDsG6bs9X2mhz3OXePgCIMwItD4fopJt7yhjyBalbAQJcwbVsmNYeDKMolZGrpm3yQR3WCs0DME1fujSz/TpFq5l0fVuLoE';

  // dart format on\n  test(\n    'unwraps a browser-compatible RSA-OAEP-SHA256 team key label',\n    () async {
    final accountKey = Uint8List.fromList(List.generate(32, (i) => 255 - i));
    final privateEnvelope = await seal(
      accountKey,
      base64Decode(privateKey),
      aad('sharing-private', [userId]),
    );
    final result = await unwrapTeamKey(
      wrapped,
      accountKey,
      privateEnvelope,
      teamId,
      userId,
      7,
    );
    expect(result, Uint8List.fromList(List.generate(32, (i) => i)));
  });

  test(\n    'wrap and unwrap preserve the team key and reject wrong context',\n    () async {
    final accountKey = Uint8List.fromList(List.generate(32, (i) => i + 1));
    final privateEnvelope = await seal(
      accountKey,
      base64Decode(privateKey),
      aad('sharing-private', [userId]),
    );
    final teamKey = Uint8List.fromList(List.generate(32, (i) => i * 3 % 256));
    final value = await wrapTeamKey(teamKey, publicKey, teamId, userId, 7);
    expect(
      await unwrapTeamKey(
        value,
        accountKey,
        privateEnvelope,
        teamId,
        userId,
        7,
      ),
      teamKey,
    );
    expect(
      () => unwrapTeamKey(
        value,
        accountKey,
        privateEnvelope,
        teamId,
        userId,
        8,
      ),
      throwsA(isA<FormatException>()),
    );
  });

  test('team item AAD round trip is revision-bound', () async {
    final key = Uint8List.fromList(List.generate(32, (i) => i));
    final payload = await encryptTeamItem(
      key,
      {'title': 'Team secret', 'password': 'not-a-real-secret'},
      teamId,
      '33333333-3333-3333-3333-333333333333',
      7,
      4,
    );
    expect(
      await decryptTeamItem(
        key,
        payload,
        teamId,
        '33333333-3333-3333-3333-333333333333',
        7,
        4,
      ),
      {'title': 'Team secret', 'password': 'not-a-real-secret'},
    );
    expect(
      () => decryptTeamItem(
        key,
        payload,
        teamId,
        '33333333-3333-3333-3333-333333333333',
        7,
        5,
      ),
      throwsA(anything),
    );
  });
}
