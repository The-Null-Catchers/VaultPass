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

  @override
  Widget build(BuildContext context) {
    if (enabled == null) {
      return ListTile(
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
      );
    }

    return SwitchListTile(
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
  }
}
