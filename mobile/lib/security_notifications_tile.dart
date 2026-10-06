import 'package:flutter/material.dart';

import 'vault_store.dart';

class SecurityNotificationsTile extends StatefulWidget {
  final VaultStore store;

  const SecurityNotificationsTile({super.key, required this.store});

  @override
  State<SecurityNotificationsTile> createState() =>
      _SecurityNotificationsTileState();
}

class _SecurityNotificationsTileState extends State<SecurityNotificationsTile> {
  bool? enabled;
  bool saving = false;
  bool rotating = false;
  String error = '';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() => error = '');
    try {
      final result = Map<String, dynamic>.from(
        await widget.store.request('/account/security-notifications') as Map,
      );
      if (!mounted) return;
      setState(() => enabled = result['new_device_email_enabled'] == true);
    } catch (exception) {
      if (!mounted) return;
      setState(() => error = exception.toString());
    }
  }

  Future<void> _update(bool next) async {
    final previous = enabled;
    if (previous == null || saving) return;
    setState(() {
      enabled = next;
      saving = true;
      error = '';
    });
    try {
      final result = Map<String, dynamic>.from(
        await widget.store.request(
              '/account/security-notifications',
              method: 'PATCH',
              body: {'new_device_email_enabled': next},
            )
            as Map,
      );
      if (!mounted) return;
      setState(() => enabled = result['new_device_email_enabled'] == true);
    } catch (exception) {
      if (!mounted) return;
      setState(() {
        enabled = previous;
        error = exception.toString();
      });
    } finally {
      if (mounted) setState(() => saving = false);
    }
  }

  Future<void> _rotate() async {
    if (rotating || widget.store.loading) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Rotate vault encryption key?'),
        content: const Text(
          'VaultPass will generate a new key on this device, re-encrypt every '
          'personal vault item locally, and atomically replace the encrypted '
          'server copies. Keep this app open until the rotation finishes.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('Rotate key'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    setState(() => rotating = true);
    try {
      final epoch = await widget.store.rotatePersonalVaultKey();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Vault encryption key rotated to epoch $epoch.')),
      );
    } catch (exception) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Key rotation failed: $exception')),
      );
    } finally {
      if (mounted) setState(() => rotating = false);
    }
  }

  Widget _rotationTile() => ListTile(
    key: const ValueKey('personal-vault-key-rotation'),
    leading: const Icon(Icons.autorenew),
    title: const Text('Rotate personal vault encryption key'),
    subtitle: Text(
      rotating
          ? 'Generating and re-encrypting locally…'
          : 'Current key epoch ${widget.store.keyVersion}. Clear keys and vault '
                'contents never leave this device.',
    ),
    trailing: rotating
        ? const SizedBox.square(
            dimension: 22,
            child: CircularProgressIndicator(strokeWidth: 2),
          )
        : const Icon(Icons.chevron_right),
    onTap: rotating || widget.store.loading ? null : _rotate,
  );

  @override
  Widget build(BuildContext context) {
    final notificationTile = enabled == null
        ? ListTile(
            leading: const Icon(Icons.mark_email_unread_outlined),
            title: const Text('New-device sign-in emails'),
            subtitle: Text(
              error.isEmpty
                  ? 'Loading security notification preference…'
                  : 'Could not load preference: $error',
            ),
            trailing: error.isEmpty
                ? const SizedBox.square(
                    dimension: 22,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : TextButton(onPressed: _load, child: const Text('Retry')),
          )
        : SwitchListTile(
            key: const ValueKey('new-device-email-switch'),
            secondary: const Icon(Icons.mark_email_unread_outlined),
            title: const Text('Email me when a new device signs in'),
            subtitle: Text(
              error.isNotEmpty
                  ? 'Could not save preference: $error'
                  : saving
                  ? 'Saving…'
                  : 'Security alerts include the device label only and never vault data.',
            ),
            value: enabled!,
            onChanged: saving ? null : _update,
          );

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [notificationTile, _rotationTile()],
    );
  }
}
