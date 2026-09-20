import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'vault_crypto.dart';
import 'vault_store.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const VaultPassApp());
}

class VaultPassApp extends StatefulWidget {
  const VaultPassApp({super.key});
  @override
  State<VaultPassApp> createState() => _VaultPassAppState();
}

class _VaultPassAppState extends State<VaultPassApp>
    with WidgetsBindingObserver {
  final store = VaultStore();
  bool dark = false;
  Timer? idle;
  void activity() {
    idle?.cancel();
    if (store.unlocked) idle = Timer(const Duration(minutes: 5), store.lock);
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    store.addListener(changed);
  }

  void changed() {
    if (mounted) setState(() {});
    activity();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden ||
        state == AppLifecycleState.detached) {
      store.lock();
    }
  }

  @override
  void dispose() {
    idle?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    store.removeListener(changed);
    store.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Listener(
    onPointerDown: (_) => activity(),
    child: MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'VaultPass',
      themeMode: dark ? ThemeMode.dark : ThemeMode.light,
      theme: theme(Brightness.light),
      darkTheme: theme(Brightness.dark),
      home: store.unlocked
          ? VaultHome(
              key: ValueKey(store.generation),
              store: store,
              dark: dark,
              onTheme: (v) => setState(() => dark = v),
            )
          : LoginPage(store: store),
    ),
  );
  ThemeData theme(Brightness b) => ThemeData(
    useMaterial3: true,
    brightness: b,
    colorScheme: ColorScheme.fromSeed(
      seedColor: const Color(0xff326a4d),
      brightness: b,
    ),
    scaffoldBackgroundColor: b == Brightness.light
        ? const Color(0xfff6f8f5)
        : const Color(0xff17231d),
    inputDecorationTheme: const InputDecorationTheme(
      border: OutlineInputBorder(
        borderRadius: BorderRadius.all(Radius.circular(12)),
      ),
      contentPadding: EdgeInsets.all(16),
    ),
    cardTheme: const CardThemeData(
      elevation: 0,
      margin: EdgeInsets.symmetric(vertical: 6),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.all(Radius.circular(16)),
      ),
    ),
  );
}

class LoginPage extends StatefulWidget {
  final VaultStore store;
  const LoginPage({super.key, required this.store});
  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final email = TextEditingController(), password = TextEditingController();
  bool register = false, busy = false;
  String error = '';
  @override
  void dispose() {
    email.dispose();
    password.dispose();
    super.dispose();
  }

  Future<void> run(Future<void> Function() action) async {
    setState(() {
      busy = true;
      error = '';
    });
    try {
      await action();
      password.clear();
    } catch (e) {
      if (mounted) setState(() => error = e.toString());
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    body: SafeArea(
      child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(28),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Icon(
                  Icons.shield_outlined,
                  size: 55,
                  color: Color(0xff477959),
                ),
                const SizedBox(height: 20),
                Text(
                  'VaultPass',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.headlineLarge,
                ),
                const SizedBox(height: 8),
                const Text(
                  'Your digital life. Under lock & key.',
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 38),
                Text(
                  register ? 'Create your private space' : 'Welcome back',
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
                const SizedBox(height: 20),
                TextField(
                  controller: email,
                  keyboardType: TextInputType.emailAddress,
                  autofillHints: const [AutofillHints.username],
                  decoration: const InputDecoration(labelText: 'Email address'),
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: password,
                  obscureText: true,
                  enableSuggestions: false,
                  autocorrect: false,
                  decoration: const InputDecoration(
                    labelText: 'Master password',
                  ),
                ),
                const SizedBox(height: 16),
                if (register)
                  const Text(
                    'Use at least 12 characters. We cannot recover a forgotten master password.',
                    style: TextStyle(fontSize: 12),
                  ),
                if (error.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    child: Text(
                      error,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  ),
                FilledButton.icon(
                  onPressed: busy
                      ? null
                      : () => run(
                          () => widget.store.login(
                            email.text.trim(),
                            password.text,
                            register: register,
                          ),
                        ),
                  icon: const Icon(Icons.lock_outline),
                  label: Text(
                    busy
                        ? 'Deriving keys…'
                        : register
                        ? 'Create encrypted vault'
                        : 'Unlock online',
                  ),
                ),
                TextButton(
                  onPressed: busy
                      ? null
                      : () => setState(() => register = !register),
                  child: Text(
                    register
                        ? 'Already have an account? Sign in'
                        : 'New here? Create an account',
                  ),
                ),
                const Divider(height: 30),
                OutlinedButton.icon(
                  onPressed: busy
                      ? null
                      : () => run(
                          () => widget.store.offlineUnlock(password.text),
                        ),
                  icon: const Icon(Icons.wifi_off),
                  label: const Text('Unlock encrypted offline cache'),
                ),
                TextButton.icon(
                  onPressed: busy
                      ? null
                      : () => run(widget.store.biometricUnlock),
                  icon: const Icon(Icons.fingerprint),
                  label: const Text('Unlock with device authentication'),
                ),
                const SizedBox(height: 25),
                const Text(
                  'Argon2id · AES-256-GCM\nYour master password stays on this device.',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 11, color: Colors.grey),
                ),
              ],
            ),
          ),
        ),
      ),
    ),
  );
}

class VaultHome extends StatefulWidget {
  final VaultStore store;
  final bool dark;
  final ValueChanged<bool> onTheme;
  const VaultHome({
    super.key,
    required this.store,
    required this.dark,
    required this.onTheme,
  });
  @override
  State<VaultHome> createState() => _VaultHomeState();
}

class _VaultHomeState extends State<VaultHome> {
  String section = 'All items', query = '', message = '';
  bool busy = false;
  String generated = generatePassword();
  double length = 24;
  VaultStore get store => widget.store;
  final sections = {
    'All items': Icons.shield_outlined,
    'Favorites': Icons.star_border,
    'Passwords': Icons.key,
    'Secure notes': Icons.note_outlined,
    'Cards': Icons.credit_card,
    'Identities': Icons.person_outline,
    'TOTP': Icons.timer_outlined,
    'Trash': Icons.delete_outline,
    'Generator': Icons.auto_awesome,
    'Security': Icons.health_and_safety_outlined,
    'Devices': Icons.devices,
    'Settings': Icons.settings_outlined,
  };
  List<dynamic> devices = [], events = [];
  Future<void> run(Future<void> Function() task) async {
    if (busy) return;
    setState(() => busy = true);
    try {
      await task();
    } catch (e) {
      if (mounted) setState(() => message = e.toString());
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> copy(String value) async {
    await Clipboard.setData(ClipboardData(text: value));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'Copied. Clipboard clears in 30 seconds where supported.',
          ),
        ),
      );
    }
    Timer(const Duration(seconds: 30), () async {
      try {
        if ((await Clipboard.getData(Clipboard.kTextPlain))?.text == value) {
          await Clipboard.setData(const ClipboardData(text: ''));
        }
      } catch (_) {
        /* OS clipboard restrictions are best-effort. */
      }
    });
  }

  Future<void> edit({Map<String, dynamic>? row}) async {
    final result = await showModalBottomSheet<Map<String, dynamic>>(
      context: context,
      isScrollControlled: true,
      useSafeArea: true,
      builder: (_) => Editor(initial: row?['data'] as Map<String, dynamic>?),
    );
    if (result != null && mounted) {
      await run(
        () =>
            store.save(result, existing: row, deleted: row?['deleted'] == true),
      );
    }
  }

  void details(Map<String, dynamic> row) {
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      useSafeArea: true,
      builder: (ctx) => Detail(
        row: row,
        copy: copy,
        onEdit: () {
          Navigator.pop(ctx);
          edit(row: row);
        },
        onTrash: () {
          Navigator.pop(ctx);
          run(
            () => store.save(
              Map<String, dynamic>.from(row['data']),
              existing: row,
              deleted: row['deleted'] != true,
            ),
          );
        },
        onFavorite: () {
          Navigator.pop(ctx);
          run(
            () => store.save(
              {
                ...Map<String, dynamic>.from(row['data']),
                'favorite': row['data']['favorite'] != true,
              },
              existing: row,
              deleted: row['deleted'] == true,
            ),
          );
        },
      ),
    );
  }

  Future<void> navigate(String name) async {
    setState(() => section = name);
    if (name == 'Devices') {
      await run(() async {
        devices = await store.request('/devices') as List;
      });
    }
    if (name == 'Security') {
      await run(() async {
        events = await store.request('/events') as List;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final visible = store.items.where((row) {
      final data = row['data'] as Map;
      final type = {
        'Passwords': 'login',
        'Secure notes': 'note',
        'Cards': 'card',
        'Identities': 'identity',
      }[section];
      return (row['deleted'] == true) == (section == 'Trash') &&
          (section != 'Favorites' || data['favorite'] == true) &&
          (section != 'TOTP' || (data['totp'] ?? '').toString().isNotEmpty) &&
          (type == null || data['type'] == type) &&
          [
            data['title'],
            data['username'],
            data['url'],
            data['tags'],
            data['folder'],
          ].join(' ').toLowerCase().contains(query.toLowerCase());
    }).toList();
    return Scaffold(
      appBar: AppBar(
        title: const Text('VaultPass'),
        actions: [
          IconButton(
            tooltip: 'Sync',
            onPressed: busy ? null : () => run(store.synchronize),
            icon: const Icon(Icons.sync),
          ),
          IconButton(
            tooltip: 'Lock vault',
            onPressed: store.lock,
            icon: const Icon(Icons.lock_outline),
          ),
        ],
      ),
      drawer: Drawer(
        child: SafeArea(
          child: ListView(
            children: [
              const Padding(
                padding: EdgeInsets.all(24),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(Icons.shield_outlined, size: 38),
                    SizedBox(height: 12),
                    Text('Personal vault', style: TextStyle(fontSize: 22)),
                    Text('Your private space'),
                  ],
                ),
              ),
              ...sections.entries.map(
                (e) => ListTile(
                  selected: section == e.key,
                  leading: Icon(e.value),
                  title: Text(e.key),
                  onTap: () {
                    Navigator.pop(context);
                    navigate(e.key);
                  },
                ),
              ),
            ],
          ),
        ),
      ),
      body: SafeArea(
        child: Column(
          children: [
            if (busy || store.loading) const LinearProgressIndicator(),
            if (message.isNotEmpty)
              MaterialBanner(
                content: Text(message),
                actions: [
                  TextButton(
                    onPressed: () => setState(() => message = ''),
                    child: const Text('Dismiss'),
                  ),
                ],
              ),
            if (store.pending.isNotEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20),
                child: Row(
                  children: [
                    Expanded(
                      child: Text(
                        '${store.pending.length} encrypted changes waiting to sync',
                        style: const TextStyle(fontSize: 12),
                      ),
                    ),
                    TextButton(
                      onPressed: () => run(store.preserveConflictAsCopy),
                      child: const Text('Keep conflict as copy'),
                    ),
                  ],
                ),
              ),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.all(20),
                children: [
                  Text(
                    section,
                    style: Theme.of(context).textTheme.headlineMedium,
                  ),
                  const SizedBox(height: 6),
                  const Text(
                    'Protected on your device. Private by design.',
                    style: TextStyle(color: Colors.grey, fontSize: 12),
                  ),
                  const SizedBox(height: 24),
                  if (section == 'Generator') ...[
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(24),
                        child: SelectableText(
                          generated,
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 22,
                          ),
                        ),
                      ),
                    ),
                    Text('Length: ${length.round()}'),
                    Slider(
                      value: length,
                      min: 12,
                      max: 128,
                      divisions: 116,
                      onChanged: (v) => setState(() => length = v),
                    ),
                    FilledButton(
                      onPressed: () => setState(
                        () => generated = generatePassword(length.round()),
                      ),
                      child: const Text('Generate password'),
                    ),
                    OutlinedButton(
                      onPressed: () => copy(generated),
                      child: const Text('Copy password'),
                    ),
                  ] else if (section == 'Settings') ...[
                    SwitchListTile(
                      title: const Text('Dark appearance'),
                      value: widget.dark,
                      onChanged: widget.onTheme,
                    ),
                    const ListTile(
                      title: Text('Automatic lock'),
                      subtitle: Text(
                        '5 minutes of inactivity. Locks when backgrounded.',
                      ),
                    ),
                    ListTile(
                      leading: const Icon(Icons.fingerprint),
                      title: const Text('Enable device-authenticated unlock'),
                      subtitle: const Text(
                        'Android: protects a local account key with the system Keystore. Device security is required.',
                      ),
                      onTap: () => run(() async {
                        await store.enableBiometric();
                        if (mounted) {
                          setState(
                            () =>
                                message = 'Device-authenticated unlock enabled',
                          );
                        }
                      }),
                    ),
                    const ListTile(
                      title: Text('Backup, import & account settings'),
                      subtitle: Text(
                        'Use the web client for encrypted backup, JSON import, email verification and master-password changes.',
                      ),
                    ),
                    ListTile(
                      leading: const Icon(Icons.logout),
                      title: const Text('Sign out and erase local cache'),
                      onTap: () => run(store.logout),
                    ),
                  ] else if (section == 'Devices')
                    ...devices.map(
                      (d) => Card(
                        child: ListTile(
                          leading: const Icon(Icons.devices),
                          title: Text(d['name']),
                          subtitle: Text(
                            d['current'] == true
                                ? 'This session'
                                : 'Other session',
                          ),
                          trailing: TextButton(
                            onPressed: d['revoked'] == true
                                ? null
                                : () => run(() async {
                                    await store.request(
                                      '/devices/${d['id']}',
                                      method: 'DELETE',
                                    );
                                    if (d['current'] == true) {
                                      store.lock();
                                    } else {
                                      devices =
                                          await store.request('/devices')
                                              as List;
                                    }
                                  }),
                            child: Text(
                              d['revoked'] == true ? 'Revoked' : 'Revoke',
                            ),
                          ),
                        ),
                      ),
                    )
                  else if (section == 'Security') ...[
                    Card(
                      child: ListTile(
                        leading: const Icon(Icons.warning_amber),
                        title: Text(
                          '${store.items.where((i) => (i['data']['password'] ?? '').toString().isNotEmpty && (i['data']['password'] as String).length < 14).length} short passwords',
                        ),
                        subtitle: const Text(
                          'Length heuristic, computed on your device',
                        ),
                      ),
                    ),
                    ...events.map(
                      (e) => ListTile(
                        leading: const Icon(Icons.shield_outlined),
                        title: Text(
                          (e['event'] as String).replaceAll('_', ' '),
                        ),
                        subtitle: Text(
                          DateTime.fromMillisecondsSinceEpoch(
                            (e['created'] as int) * 1000,
                          ).toLocal().toString(),
                        ),
                      ),
                    ),
                  ] else ...[
                    TextField(
                      onChanged: (v) => setState(() => query = v),
                      decoration: const InputDecoration(
                        prefixIcon: Icon(Icons.search),
                        hintText: 'Search this vault locally',
                      ),
                    ),
                    const SizedBox(height: 18),
                    if (visible.isEmpty)
                      const Padding(
                        padding: EdgeInsets.symmetric(vertical: 60),
                        child: Column(
                          children: [
                            Icon(
                              Icons.lock_outline,
                              size: 48,
                              color: Colors.grey,
                            ),
                            SizedBox(height: 18),
                            Text('A private home for your secrets'),
                            SizedBox(height: 8),
                            Text(
                              'Add your first item with the + button.',
                              style: TextStyle(color: Colors.grey),
                            ),
                          ],
                        ),
                      ),
                    ...visible.map((row) {
                      final d = row['data'] as Map;
                      return Card(
                        child: ListTile(
                          contentPadding: const EdgeInsets.symmetric(
                            horizontal: 16,
                            vertical: 9,
                          ),
                          leading: CircleAvatar(
                            child: Icon(
                              d['type'] == 'note'
                                  ? Icons.note_outlined
                                  : Icons.key,
                            ),
                          ),
                          title: Text(d['title'].toString()),
                          subtitle: Text(
                            (d['username'] ?? d['type']).toString(),
                          ),
                          trailing: Icon(
                            d['favorite'] == true
                                ? Icons.star
                                : Icons.chevron_right,
                            size: 20,
                          ),
                          onTap: () => details(row),
                        ),
                      );
                    }),
                  ],
                  const SizedBox(height: 80),
                ],
              ),
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => edit(),
        icon: const Icon(Icons.add),
        label: const Text('Add item'),
      ),
    );
  }
}

class Editor extends StatefulWidget {
  final Map<String, dynamic>? initial;
  const Editor({super.key, this.initial});
  @override
  State<Editor> createState() => _EditorState();
}

class _EditorState extends State<Editor> {
  late final Map<String, TextEditingController> fields;
  late String type;
  @override
  void initState() {
    super.initState();
    fields = {
      for (final key in [
        'title',
        'username',
        'password',
        'url',
        'folder',
        'tags',
        'totp',
        'notes',
      ])
        key: TextEditingController(
          text: widget.initial?[key]?.toString() ?? '',
        ),
    };
    type = widget.initial?['type']?.toString() ?? 'login';
  }

  @override
  void dispose() {
    for (final c in fields.values) {
      c.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Padding(
    padding: EdgeInsets.fromLTRB(
      24,
      24,
      24,
      MediaQuery.viewInsetsOf(context).bottom + 24,
    ),
    child: SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            'Encrypted item',
            style: Theme.of(context).textTheme.headlineSmall,
          ),
          const SizedBox(height: 20),
          DropdownButtonFormField<String>(
            initialValue: type,
            items: [
              'login',
              'note',
              'card',
              'identity',
              'api',
              'recovery',
              'ssh',
            ].map((s) => DropdownMenuItem(value: s, child: Text(s))).toList(),
            onChanged: (v) => setState(() => type = v!),
            decoration: const InputDecoration(labelText: 'Item type'),
          ),
          ...fields.entries.map(
            (e) => Padding(
              padding: const EdgeInsets.only(top: 14),
              child: TextField(
                controller: e.value,
                obscureText: e.key == 'password' || e.key == 'totp',
                enableSuggestions: false,
                autocorrect: false,
                maxLines: e.key == 'notes' ? 4 : 1,
                decoration: InputDecoration(
                  labelText: e.key == 'notes'
                      ? 'Notes / additional fields'
                      : e.key,
                  suffixIcon: e.key == 'password'
                      ? IconButton(
                          tooltip: 'Generate password',
                          onPressed: () =>
                              fields['password']!.text = generatePassword(),
                          icon: const Icon(Icons.auto_awesome),
                        )
                      : null,
                ),
              ),
            ),
          ),
          const SizedBox(height: 24),
          FilledButton.icon(
            onPressed: () {
              if (fields['title']!.text.trim().isEmpty) return;
              Navigator.pop(context, {
                'type': type,
                'favorite': widget.initial?['favorite'] ?? false,
                for (final e in fields.entries) e.key: e.value.text,
              });
            },
            icon: const Icon(Icons.lock_outline),
            label: const Text('Save encrypted item'),
          ),
        ],
      ),
    ),
  );
}

class Detail extends StatefulWidget {
  final Map<String, dynamic> row;
  final Future<void> Function(String) copy;
  final VoidCallback onEdit, onTrash, onFavorite;
  const Detail({
    super.key,
    required this.row,
    required this.copy,
    required this.onEdit,
    required this.onTrash,
    required this.onFavorite,
  });
  @override
  State<Detail> createState() => _DetailState();
}

class _DetailState extends State<Detail> {
  bool visible = false;
  String code = '';
  Timer? timer;
  @override
  void initState() {
    super.initState();
    update();
    timer = Timer.periodic(const Duration(seconds: 1), (_) => update());
  }

  Future<void> update() async {
    final seed = (widget.row['data']['totp'] ?? '').toString();
    if (seed.isEmpty) return;
    try {
      final value = await totp(seed);
      if (mounted) setState(() => code = value);
    } catch (_) {
      if (mounted) setState(() => code = 'Invalid seed');
    }
  }

  @override
  void dispose() {
    timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final data = widget.row['data'] as Map;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(28),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Icon(Icons.shield_outlined, size: 34),
              const Spacer(),
              IconButton(
                onPressed: widget.onFavorite,
                icon: Icon(
                  data['favorite'] == true ? Icons.star : Icons.star_outline,
                ),
              ),
            ],
          ),
          Text(
            data['title'].toString(),
            style: Theme.of(context).textTheme.headlineMedium,
          ),
          const SizedBox(height: 25),
          ...['username', 'password', 'url', 'folder', 'tags', 'notes']
              .where((k) => (data[k] ?? '').toString().isNotEmpty)
              .map(
                (key) => ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(
                    key,
                    style: const TextStyle(fontSize: 11, color: Colors.grey),
                  ),
                  subtitle: Text(
                    key == 'password' && !visible
                        ? '••••••••••••'
                        : data[key].toString(),
                  ),
                  trailing: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (key == 'password')
                        IconButton(
                          tooltip: 'Toggle visibility',
                          onPressed: () => setState(() => visible = !visible),
                          icon: Icon(
                            visible ? Icons.visibility_off : Icons.visibility,
                          ),
                        ),
                      IconButton(
                        tooltip: 'Copy $key',
                        onPressed: () => widget.copy(data[key].toString()),
                        icon: const Icon(Icons.copy, size: 19),
                      ),
                    ],
                  ),
                ),
              ),
          if (code.isNotEmpty)
            ListTile(
              title: const Text('Authenticator'),
              subtitle: Text(
                code,
                style: const TextStyle(fontSize: 28, letterSpacing: 5),
              ),
              trailing: IconButton(
                tooltip: 'Copy code',
                onPressed: () => widget.copy(code),
                icon: const Icon(Icons.copy),
              ),
            ),
          const SizedBox(height: 20),
          FilledButton(
            onPressed: widget.onEdit,
            child: const Text('Edit item'),
          ),
          TextButton(
            onPressed: widget.onTrash,
            child: Text(
              widget.row['deleted'] == true ? 'Restore item' : 'Move to trash',
            ),
          ),
          const SizedBox(height: 20),
          const Text(
            'Every field is encrypted on your device.',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 11, color: Colors.grey),
          ),
        ],
      ),
    );
  }
}
