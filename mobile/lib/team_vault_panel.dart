import 'package:flutter/material.dart';

import 'vault_store.dart';

class TeamVaultPanel extends StatefulWidget {
  final VaultStore store;

  const TeamVaultPanel({super.key, required this.store});

  @override
  State<TeamVaultPanel> createState() => _TeamVaultPanelState();
}

class _TeamVaultPanelState extends State<TeamVaultPanel> {
  bool busy = false;
  String message = '';

  VaultStore get store => widget.store;

  Future<void> run(Future<void> Function() action) async {
    if (busy) return;
    setState(() {
      busy = true;
      message = '';
    });
    try {
      await action();
    } catch (error) {
      if (mounted) setState(() => message = error.toString());
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> createTeam() async {
    final controller = TextEditingController();
    final name = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Create team vault'),
        content: TextField(
          controller: controller,
          autofocus: true,
          maxLength: 80,
          decoration: const InputDecoration(labelText: 'Team name'),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, controller.text),
            child: const Text('Create'),
          ),
        ],
      ),
    );
    controller.dispose();
    if (name != null && name.trim().isNotEmpty) {
      await run(() => store.createTeam(name));
    }
  }

  Future<void> editItem({Map<String, dynamic>? row}) async {
    final initial = row?['data'] is Map
        ? Map<String, dynamic>.from(row!['data'] as Map)
        : <String, dynamic>{};
    final result = await showModalBottomSheet<Map<String, dynamic>>(
      context: context,
      isScrollControlled: true,
      useSafeArea: true,
      builder: (_) => _TeamItemEditor(initial: initial),
    );
    if (result == null || !mounted) return;
    await run(() async {
      await store.saveTeamItem(result, existing: row);
      await store.synchronizeTeam();
    });
  }

  Future<void> refresh() async {
    await run(() async {
      final selectedId = store.selectedTeam?['id']?.toString();
      await store.loadTeamOverview();
      if (selectedId != null) {
        final latest = store.teams
            .where((team) => team['id'].toString() == selectedId)
            .firstOrNull;
        if (latest != null) await store.openTeam(latest);
      }
    });
  }

  Widget invitationCard(Map<String, dynamic> invitation) {
    final expires = DateTime.fromMillisecondsSinceEpoch(
      ((invitation['expires'] as num?)?.toInt() ?? 0) * 1000,
    ).toLocal();
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              invitation['team_name']?.toString() ?? 'Team invitation',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 4),
            Text(
              '${invitation['role']?.toString().replaceAll('_', ' ')} · '
              'expires ${MaterialLocalizations.of(context).formatShortDate(expires)}',
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              children: [
                FilledButton(
                  onPressed: busy
                      ? null
                      : () => run(
                          () => store.acceptTeamInvitation(
                            invitation['id'].toString(),
                          ),
                        ),
                  child: const Text('Accept'),
                ),
                OutlinedButton(
                  onPressed: busy
                      ? null
                      : () => run(
                          () => store.declineTeamInvitation(
                            invitation['id'].toString(),
                          ),
                        ),
                  child: const Text('Decline'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget itemCard(Map<String, dynamic> row) {
    final data = Map<String, dynamic>.from(row['data'] as Map);
    final deleted = row['deleted'] == true;
    return Card(
      child: ListTile(
        leading: Icon(deleted ? Icons.delete_outline : Icons.key_outlined),
        title: Text(
          (data['title']?.toString().trim().isNotEmpty ?? false)
              ? data['title'].toString()
              : 'Untitled',
        ),
        subtitle: Text(
          [
            if ((data['username'] ?? '').toString().isNotEmpty)
              data['username'].toString(),
            'Encrypted revision ${row['version']}',
          ].join(' · '),
        ),
        trailing: store.teamCanEdit
            ? PopupMenuButton<String>(
                onSelected: (value) {
                  if (value == 'edit') {
                    editItem(row: row);
                  } else if (value == 'trash') {
                    run(() async {
                      await store.saveTeamItem(
                        data,
                        existing: row,
                        deleted: !deleted,
                      );
                      await store.synchronizeTeam();
                    });
                  }
                },
                itemBuilder: (_) => [
                  const PopupMenuItem(value: 'edit', child: Text('Edit')),
                  PopupMenuItem(
                    value: 'trash',
                    child: Text(deleted ? 'Restore' : 'Move to trash'),
                  ),
                ],
              )
            : const Icon(Icons.visibility_outlined),
        onTap: () => showModalBottomSheet<void>(
          context: context,
          useSafeArea: true,
          builder: (_) => _TeamItemDetails(data: data, row: row),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final selected = store.selectedTeam;
    final active = store.teamItems
        .where((row) => row['deleted'] != true)
        .toList();
    final trash = store.teamItems
        .where((row) => row['deleted'] == true)
        .toList();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(
              child: Text(
                'Team vaults',
                style: Theme.of(context).textTheme.headlineMedium,
              ),
            ),
            IconButton(
              tooltip: 'Refresh teams',
              onPressed: busy || store.teamLoading ? null : refresh,
              icon: const Icon(Icons.refresh),
            ),
          ],
        ),
        const SizedBox(height: 6),
        const Text(
          'Team keys and item plaintext stay on this device. '
          'The server receives wrapped keys and ciphertext.',
          style: TextStyle(color: Colors.grey, fontSize: 12),
        ),
        if (busy || store.teamLoading) ...[
          const SizedBox(height: 12),
          const LinearProgressIndicator(),
        ],
        if (message.isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(top: 12),
            child: MaterialBanner(
              content: Text(message),
              actions: [
                TextButton(
                  onPressed: () => setState(() => message = ''),
                  child: const Text('Dismiss'),
                ),
              ],
            ),
          ),
        const SizedBox(height: 20),
        Row(
          children: [
            Expanded(
              child: Text(
                store.teams.isEmpty
                    ? 'No cached team vaults'
                    : '${store.teams.length} team vault(s)',
              ),
            ),
            FilledButton.icon(
              onPressed:
                  busy || store.teamLoading || store.sharingIdentity == null
                  ? null
                  : createTeam,
              icon: const Icon(Icons.group_add_outlined),
              label: const Text('Create'),
            ),
          ],
        ),
        if (store.sharingIdentity == null)
          const Padding(
            padding: EdgeInsets.only(top: 12),
            child: Card(
              child: ListTile(
                leading: Icon(Icons.info_outline),
                title: Text('Sharing identity required'),
                subtitle: Text(
                  'Existing team vaults require your account sharing keypair. '
                  'Enable encrypted sharing on the web client if this account '
                  'does not have one yet.',
                ),
              ),
            ),
          ),
        const SizedBox(height: 8),
        ...store.teams.map(
          (team) => Card(
            child: ListTile(
              selected: selected?['id'] == team['id'],
              leading: const Icon(Icons.groups_outlined),
              title: Text(team['name']?.toString() ?? 'Team vault'),
              subtitle: Text(
                '${team['role']?.toString().replaceAll('_', ' ')} · '
                'key epoch ${team['key_version']}',
              ),
              trailing: const Icon(Icons.chevron_right),
              onTap: busy || store.teamLoading
                  ? null
                  : () => run(() => store.openTeam(team)),
            ),
          ),
        ),
        const SizedBox(height: 20),
        Text(
          'Incoming invitations',
          style: Theme.of(context).textTheme.titleLarge,
        ),
        const SizedBox(height: 8),
        if (store.incomingTeamInvitations.isEmpty)
          const Text(
            'No pending invitations. Refresh when you are online to check.',
            style: TextStyle(color: Colors.grey),
          ),
        ...store.incomingTeamInvitations.map(invitationCard),
        if (selected != null) ...[
          const Divider(height: 40),
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      selected['name']?.toString() ?? 'Team vault',
                      style: Theme.of(context).textTheme.titleLarge,
                    ),
                    Text(
                      '${selected['role']?.toString().replaceAll('_', ' ')} · '
                      'key epoch ${selected['key_version']}',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ),
              ),
              IconButton(
                tooltip: 'Sync selected team',
                onPressed: busy || store.teamLoading
                    ? null
                    : () => run(store.synchronizeTeam),
                icon: const Icon(Icons.sync),
              ),
            ],
          ),
          if (store.teamPending.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(
                '${store.teamPending.length} encrypted team change(s) waiting to sync',
                style: const TextStyle(fontSize: 12),
              ),
            ),
          if (selected['role'] == 'read_only')
            const Padding(
              padding: EdgeInsets.only(top: 12),
              child: Card(
                child: ListTile(
                  leading: Icon(Icons.visibility_outlined),
                  title: Text('Read-only access'),
                  subtitle: Text(
                    'Editing controls are disabled locally and the API also '
                    'enforces this role server-side.',
                  ),
                ),
              ),
            ),
          const SizedBox(height: 12),
          if (store.teamCanEdit)
            FilledButton.icon(
              onPressed: busy || store.teamLoading ? null : () => editItem(),
              icon: const Icon(Icons.add),
              label: const Text('Add encrypted team item'),
            ),
          const SizedBox(height: 12),
          if (active.isEmpty)
            const Text(
              'No active team items.',
              style: TextStyle(color: Colors.grey),
            ),
          ...active.map(itemCard),
          if (trash.isNotEmpty) ...[
            const SizedBox(height: 20),
            Text('Trash', style: Theme.of(context).textTheme.titleMedium),
            ...trash.map(itemCard),
          ],
        ],
      ],
    );
  }
}

class _TeamItemEditor extends StatefulWidget {
  final Map<String, dynamic> initial;

  const _TeamItemEditor({required this.initial});

  @override
  State<_TeamItemEditor> createState() => _TeamItemEditorState();
}

class _TeamItemEditorState extends State<_TeamItemEditor> {
  late final TextEditingController title;
  late final TextEditingController username;
  late final TextEditingController password;
  late final TextEditingController notes;

  @override
  void initState() {
    super.initState();
    title = TextEditingController(
      text: widget.initial['title']?.toString() ?? '',
    );
    username = TextEditingController(
      text: widget.initial['username']?.toString() ?? '',
    );
    password = TextEditingController(
      text: widget.initial['password']?.toString() ?? '',
    );
    notes = TextEditingController(
      text: widget.initial['notes']?.toString() ?? '',
    );
  }

  @override
  void dispose() {
    title.dispose();
    username.dispose();
    password.dispose();
    notes.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Padding(
    padding: EdgeInsets.only(
      left: 20,
      right: 20,
      top: 20,
      bottom: MediaQuery.viewInsetsOf(context).bottom + 20,
    ),
    child: SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            widget.initial.isEmpty ? 'New team item' : 'Edit team item',
            style: Theme.of(context).textTheme.headlineSmall,
          ),
          const SizedBox(height: 20),
          TextField(
            controller: title,
            autofocus: true,
            onChanged: (_) => setState(() {}),
            decoration: const InputDecoration(labelText: 'Title'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: username,
            decoration: const InputDecoration(labelText: 'Username'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: password,
            obscureText: true,
            enableSuggestions: false,
            autocorrect: false,
            decoration: const InputDecoration(labelText: 'Password / secret'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: notes,
            minLines: 3,
            maxLines: 8,
            decoration: const InputDecoration(labelText: 'Notes'),
          ),
          const SizedBox(height: 20),
          FilledButton(
            onPressed: title.text.trim().isEmpty
                ? null
                : () => Navigator.pop(context, {
                    'title': title.text.trim(),
                    'username': username.text,
                    'password': password.text,
                    'notes': notes.text,
                  }),
            child: const Text('Save encrypted item'),
          ),
        ],
      ),
    ),
  );
}

class _TeamItemDetails extends StatelessWidget {
  final Map<String, dynamic> data;
  final Map<String, dynamic> row;

  const _TeamItemDetails({required this.data, required this.row});

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.all(24),
    child: Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          data['title']?.toString() ?? 'Untitled',
          style: Theme.of(context).textTheme.headlineSmall,
        ),
        const SizedBox(height: 12),
        if ((data['username'] ?? '').toString().isNotEmpty)
          SelectableText('Username: ${data['username']}'),
        if ((data['password'] ?? '').toString().isNotEmpty)
          SelectableText('Password / secret: ${data['password']}'),
        if ((data['notes'] ?? '').toString().isNotEmpty) ...[
          const SizedBox(height: 12),
          SelectableText(data['notes'].toString()),
        ],
        const SizedBox(height: 12),
        Text(
          'Encrypted revision ${row['version']}',
          style: Theme.of(context).textTheme.bodySmall,
        ),
      ],
    ),
  );
}
