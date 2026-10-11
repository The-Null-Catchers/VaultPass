import 'dart:math';

const _left = [
  'amber',
  'brisk',
  'cedar',
  'dawn',
  'ember',
  'frost',
  'gold',
  'harbor',
  'indigo',
  'jade',
  'kind',
  'lunar',
  'mist',
  'north',
  'opal',
  'quiet',
];

const _right = [
  'anchor',
  'bird',
  'cloud',
  'drift',
  'field',
  'grove',
  'hill',
  'island',
  'journey',
  'kettle',
  'leaf',
  'meadow',
  'night',
  'orbit',
  'pine',
  'river',
];

class PassphraseResult {
  final String passphrase;
  final int entropy;
  final String estimate;

  const PassphraseResult({
    required this.passphrase,
    required this.entropy,
    required this.estimate,
  });
}

String _word(int index) => '${_left[index >> 4]}${_right[index & 15]}';

PassphraseResult generatePassphrase({
  int words = 8,
  String separator = '-',
  bool capitalize = false,
  bool includeNumber = false,
  Random? random,
}) {
  if (words < 6 || words > 12) {
    throw ArgumentError('Choose 6–12 words');
  }
  if (!const ['-', '.', '_', ' '].contains(separator)) {
    throw ArgumentError('Unsupported separator');
  }
  final source = random ?? Random.secure();
  final selected = <String>[];
  for (var index = 0; index < words; index++) {
    var word = _word(source.nextInt(256));
    if (capitalize) word = '${word[0].toUpperCase()}${word.substring(1)}';
    selected.add(word);
  }
  if (includeNumber) {
    selected.add(source.nextInt(100).toString().padLeft(2, '0'));
  }
  final entropy = words * 8 + (includeNumber ? log(100) / ln2 : 0);
  return PassphraseResult(
    passphrase: selected.join(separator),
    entropy: entropy.floor(),
    estimate:
        "Entropy is based on independent uniform choices from VaultPass's 256-token passphrase dictionary.",
  );
}
