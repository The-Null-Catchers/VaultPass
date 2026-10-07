import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:vaultpass/generator.dart';

class SequenceRandom implements Random {
  final List<int> values;
  var index = 0;

  SequenceRandom(this.values);

  @override
  int nextInt(int max) => values[index++] % max;

  @override
  bool nextBool() => nextInt(2) == 1;

  @override
  double nextDouble() => nextInt(1 << 20) / (1 << 20);
}

void main() {
  test('builds an eight-word passphrase with 64 bits of dictionary entropy', () {
    final result = generatePassphrase(
      random: SequenceRandom([0, 17, 34, 51, 68, 85, 102, 119]),
    );

    expect(
      result.passphrase,
      'amberanchor-briskbird-cedarcloud-dawndrift-emberfield-'
      'frostgrove-goldhill-harborisland',
    );
    expect(result.entropy, 64);
  });

  test('supports capitalization, custom separator, and numeric token', () {
    final result = generatePassphrase(
      words: 6,
      separator: '.',
      capitalize: true,
      includeNumber: true,
      random: SequenceRandom(List<int>.filled(7, 0)),
    );

    expect(
      result.passphrase,
      'Amberanchor.Amberanchor.Amberanchor.Amberanchor.Amberanchor.'
      'Amberanchor.00',
    );
    expect(result.entropy, 54);
  });

  test('rejects unsupported options', () {
    expect(
      () => generatePassphrase(words: 5, random: SequenceRandom([0])),
      throwsArgumentError,
    );
    expect(
      () => generatePassphrase(separator: '/', random: SequenceRandom([0])),
      throwsArgumentError,
    );
  });
}
