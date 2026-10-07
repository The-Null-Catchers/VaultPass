import 'package:flutter/material.dart';

import 'generator.dart';
import 'vault_crypto.dart';

class GeneratorPanel extends StatefulWidget {
  final Future<void> Function(String value) copy;

  const GeneratorPanel({super.key, required this.copy});

  @override
  State<GeneratorPanel> createState() => _GeneratorPanelState();
}

class _GeneratorPanelState extends State<GeneratorPanel> {
  bool passphrase = false;
  bool symbols = true;
  bool capitalize = false;
  bool includeNumber = false;
  double length = 24;
  double words = 8;
  String separator = '-';
  String generated = generatePassword();
  int? entropy;

  void generateValue() {
    if (passphrase) {
      final result = generatePassphrase(
        words: words.round(),
        separator: separator,
        capitalize: capitalize,
        includeNumber: includeNumber,
      );
      setState(() {
        generated = result.passphrase;
        entropy = result.entropy;
      });
    } else {
      setState(() {
        generated = generatePassword(length.round());
        entropy = null;
      });
    }
  }

  void selectMode(bool next) {
    setState(() => passphrase = next);
    generateValue();
  }

  @override
  Widget build(BuildContext context) => ListView(
    padding: const EdgeInsets.all(20),
    children: [
      SegmentedButton<bool>(
        segments: const [
          ButtonSegment(value: false, label: Text('Password')),
          ButtonSegment(value: true, label: Text('Passphrase')),
        ],
        selected: {passphrase},
        onSelectionChanged: (value) => selectMode(value.first),
      ),
      const SizedBox(height: 20),
      SelectableText(
        generated,
        textAlign: TextAlign.center,
        style: Theme.of(context).textTheme.titleLarge,
      ),
      const SizedBox(height: 20),
      if (!passphrase) ...[
        Text('Length · ${length.round()}'),
        Slider(
          value: length,
          min: 12,
          max: 128,
          divisions: 116,
          onChanged: (value) => setState(() => length = value),
        ),
        SwitchListTile(
          value: symbols,
          onChanged: (value) => setState(() => symbols = value),
          title: const Text('Include symbols'),
        ),
      ] else ...[
        Text('Words · ${words.round()}'),
        Slider(
          value: words,
          min: 6,
          max: 12,
          divisions: 6,
          onChanged: (value) => setState(() => words = value),
        ),
        DropdownButtonFormField<String>(
          initialValue: separator,
          decoration: const InputDecoration(labelText: 'Separator'),
          items: const [
            DropdownMenuItem(value: '-', child: Text('Hyphen')),
            DropdownMenuItem(value: '.', child: Text('Dot')),
            DropdownMenuItem(value: '_', child: Text('Underscore')),
            DropdownMenuItem(value: ' ', child: Text('Space')),
          ],
          onChanged: (value) => setState(() => separator = value ?? '-'),
        ),
        SwitchListTile(
          value: capitalize,
          onChanged: (value) => setState(() => capitalize = value),
          title: const Text('Capitalize each token'),
        ),
        SwitchListTile(
          value: includeNumber,
          onChanged: (value) => setState(() => includeNumber = value),
          title: const Text('Add a two-digit token'),
        ),
      ],
      const SizedBox(height: 12),
      FilledButton.icon(
        onPressed: generateValue,
        icon: const Icon(Icons.auto_awesome),
        label: Text('Generate ${passphrase ? 'passphrase' : 'password'}'),
      ),
      OutlinedButton.icon(
        onPressed: () => widget.copy(generated),
        icon: const Icon(Icons.copy),
        label: const Text('Copy'),
      ),
      const SizedBox(height: 8),
      Text(
        entropy == null
            ? 'Generated locally. Nothing is sent to VaultPass servers.'
            : 'Estimated discrete-choice entropy: $entropy bits. This is not a security guarantee.',
        textAlign: TextAlign.center,
        style: Theme.of(context).textTheme.bodySmall,
      ),
    ],
  );
}
