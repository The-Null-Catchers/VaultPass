"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { ShieldCheck, LockKeyhole, Search, Plus, KeyRound, FileText, CreditCard, UserRound, Star, Trash2, WandSparkles, Activity, MonitorSmartphone, Settings, LogOut, Copy, Eye, EyeOff, Menu, X, RefreshCw, Download, Upload, Clock3, Code2 } from "lucide-react";
import { api, clearTokens, setTokens } from "../lib/api";
import { Bundle, Envelope, PROFILE, context, createAccount, createRecovery, decryptJSON, derive, encryptJSON, open, rewrap, unlock, unlockRecovery } from "../lib/crypto";
import { breachCount, generate, health } from "../lib/generator";
import { createIdentity, fingerprint, encryptShare, decryptShare } from "../lib/sharing";
import { restoreBackup, validateItem } from "../lib/backup";
import { totp } from "../lib/totp";
import { authenticatePasskey, createPasskey } from "../lib/passkeys";
import type { AuthenticationOptions, RegistrationOptions } from "../lib/passkeys";
type Data = {
  title: string;
  type: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  tags: string;
  folder: string;
  favorite: boolean;
  totp: string;
};
type Row = {
  id: string;
  version: number;
  payload: Envelope;
  deleted: boolean;
  purged: boolean;
  updated: number;
};
type Entry = Row & { data: Data };
type Session = {
  user_id: string;
  bundle: Bundle;
  access_token: string;
  refresh_token: string;
};
type Device = {
  id: string;
  name: string;
  created: number;
  latest: number;
  current: boolean;
  revoked: boolean;
};
type Shared = {
  id: string;
  sender_id: string;
  recipient_id: string;
  expires: number;
  revoked: boolean;
  outgoing: boolean;
  wrapped_key?: string;
  payload?: Envelope;
  data?: Data;
};
type Event = { id: string; event: string; created: number };
type Passkey = {
  id: string;
  name: string;
  created: number;
  latest: number;
  device_type: string;
  backed_up: boolean;
  transports: string[];
};
type PasskeyPrompt = {
  mfa_required: true;
  token: string;
  expires_in: number;
  public_key: AuthenticationOptions;
};
const blank = (): Data => ({
  title: "",
  type: "login",
  username: "",
  password: "",
  url: "",
  notes: "",
  tags: "",
  folder: "",
  favorite: false,
  totp: "",
});
const navigation = [
  { name: "All items", icon: ShieldCheck },
  { name: "Favorites", icon: Star },
  { name: "Passwords", icon: KeyRound },
  { name: "Secure notes", icon: FileText },
  { name: "Cards", icon: CreditCard },
  { name: "Identities", icon: UserRound },
  { name: "Developer", icon: Code2 },
  { name: "TOTP", icon: Clock3 },
  { name: "Trash", icon: Trash2 },
  { name: "Generator", icon: WandSparkles },
  { name: "Security", icon: Activity },
  { name: "Devices", icon: MonitorSmartphone },
  { name: "Sharing", icon: ShieldCheck },
  { name: "Settings", icon: Settings },
];
const labels: Record<string, string> = {
  login: "Login",
  note: "Secure note",
  card: "Payment card",
  identity: "Identity",
  api: "API credential",
  recovery: "Recovery codes",
  ssh: "Developer secret",
};
export default function Home() {
  const [session, setSession] = useState<Session | null>(null),
    [mode, setMode] = useState("login"),
    [email, setEmail] = useState(""),
    [master, setMaster] = useState(""),
    [recoveryInput, setRecoveryInput] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState("");
  const accountKey = useRef<Uint8Array | null>(null),
    vaultKey = useRef<Uint8Array | null>(null),
    vaultId = useRef("");
  const [items, setItems] = useState<Entry[]>([]),
    [section, setSection] = useState("All items"),
    [query, setQuery] = useState(""),
    [selected, setSelected] = useState<string | null>(null),
    [editing, setEditing] = useState(false),
    [draft, setDraft] = useState<Data>(blank()),
    [show, setShow] = useState(false),
    [mobile, setMobile] = useState(false),
    [dark, setDark] = useState(false),
    [otp, setOtp] = useState(""),
    [tick, setTick] = useState(0);
  const [devices, setDevices] = useState<Device[]>([]),
    [events, setEvents] = useState<Event[]>([]),
    [length, setLength] = useState(24),
    [symbols, setSymbols] = useState(true),
    [generated, setGenerated] = useState(""),
    [authConfirm, setAuthConfirm] = useState(""),
    [newMaster, setNewMaster] = useState(""),
    [verifyToken, setVerifyToken] = useState(""),
    [history, setHistory] = useState<{ version: number; data: Data }[]>([]);
  const [recoveryEnabled, setRecoveryEnabled] = useState(false),
    [recoveryContext, setRecoveryContext] = useState(""),
    [shownRecovery, setShownRecovery] = useState("");
  const [passkeys, setPasskeys] = useState<Passkey[]>([]),
    [passkeyName, setPasskeyName] = useState("This device"),
    [passkeyMaster, setPasskeyMaster] = useState("");
  const [shares, setShares] = useState<Shared[]>([]),
    [identity, setIdentity] = useState<{
      public_key: string;
      private_key: Envelope;
    } | null>(null),
    [ownFingerprint, setOwnFingerprint] = useState(""),
    [recipient, setRecipient] = useState(""),
    [sharingItem, setSharingItem] = useState(""),
    [recipientKey, setRecipientKey] = useState<{
      user_id: string;
      public_key: string;
      fingerprint: string;
    } | null>(null),
    [verifiedFingerprint, setVerifiedFingerprint] = useState(false);
  const locking = useRef(false);
  const selectedItem = items.find((i) => i.id === selected);
  const notify = (text: string) => {
    setNotice(text);
    window.setTimeout(() => setNotice(""), 5000);
  };
  const lock = useCallback(() => {
    if (locking.current) return;
    locking.current = true;
    accountKey.current?.fill(0);
    vaultKey.current?.fill(0);
    clearTokens();
    window.location.reload();
  }, []);
  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Operation failed");
    } finally {
      setBusy(false);
    }
  };
  const sync = async () => {
    const results: Entry[] = [];
    let cursor = 0,
      more = true;
    while (more) {
      const page = await api<{
        cursor: number;
        has_more: boolean;
        items: Row[];
      }>(`/vaults/${vaultId.current}/sync?after=${cursor}`);
      cursor = page.cursor;
      more = page.has_more;
      for (const row of page.items)
        if (!row.purged)
          results.push({
            ...row,
            data: await decryptJSON<Data>(vaultKey.current!, row.payload, context("item", vaultId.current, row.id, row.version)),
          });
    }
    setItems(results.sort((a, b) => b.updated - a.updated));
    return results;
  };
  const login = async () =>
    run(async () => {
      if (mode === "recover") {
        try {
          const lookup = await api<{ context: string; account_key: Envelope }>("/auth/recovery/lookup", "POST", { email });
          const recovered = await unlockRecovery(recoveryInput, lookup.context, lookup.account_key);
          try {
            const challenge = await api<{ token: string; user_id: string }>("/auth/recovery/verify", "POST", { email, recovery_auth_secret: recovered.recoveryAuth });
            const update = await rewrap(master, challenge.user_id, recovered.accountKey);
            await api("/auth/recovery/complete", "POST", {
              token: challenge.token,
              ...update,
            });
          } finally {
            recovered.accountKey.fill(0);
          }
          setMode("login");
          setMaster("");
          setRecoveryInput("");
          notify("Recovery complete. Sign in with your new master password and create a new recovery key.");
        } catch {
          throw new Error("Recovery failed. Check the account, recovery key, and new master password.");
        }
        return;
      }
      let result: Session;
      if (mode === "register") {
        const created = await createAccount(master);
        try {
          result = await api<Session>("/auth/register", "POST", {
            id: created.id,
            email,
            auth_secret: created.auth,
            bundle: created.bundle,
            vault_id: created.vaultId,
            wrapped_vault_key: created.wrappedVaultKey,
            device: "Web browser",
          });
        } finally {
          created.accountKey.fill(0);
          created.vaultKey.fill(0);
        }
      } else {
        const params = await api<{ salt: string; profile: string }>("/auth/lookup", "POST", { email });
        if (params.profile !== PROFILE) throw new Error("Unsupported key derivation profile");
        const derived = await derive(master, params.salt);
        try {
          const response = await api<Session | PasskeyPrompt>("/auth/login", "POST", {
            email,
            auth_secret: derived.auth,
            device: "Web browser",
          });
          if ("mfa_required" in response) {
            const credential = await authenticatePasskey(response.public_key);
            result = await api<Session>("/auth/passkey/complete", "POST", {
              token: response.token,
              credential,
            });
          } else result = response;
        } finally {
          derived.wrap.fill(0);
        }
      }
      setTokens(result.access_token, result.refresh_token);
      accountKey.current = await unlock(master, result.user_id, result.bundle);
      const vaults = await api<{ id: string; wrapped_key: Envelope }[]>("/vaults");
      if (!vaults.length) throw new Error("Account has no vault");
      vaultId.current = vaults[0].id;
      vaultKey.current = await open(accountKey.current, vaults[0].wrapped_key, context("vault", result.user_id, vaultId.current));
      setMaster("");
      setSession({ ...result, access_token: "", refresh_token: "" });
      await sync();
    });
  useEffect(() => {
    if (!session) return;
    let timer: ReturnType<typeof setTimeout>;
    const activity = () => {
      clearTimeout(timer);
      timer = setTimeout(lock, 5 * 60 * 1000);
    };
    const hidden = () => {
      if (document.hidden) lock();
    };
    activity();
    window.addEventListener("pointerdown", activity);
    window.addEventListener("keydown", activity);
    document.addEventListener("visibilitychange", hidden);
    return () => {
      clearTimeout(timer);
      window.removeEventListener("pointerdown", activity);
      window.removeEventListener("keydown", activity);
      document.removeEventListener("visibilitychange", hidden);
    };
  }, [session, lock]);
  useEffect(() => {
    const t = setInterval(() => setTick(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    let active = true;
    if (selectedItem?.data.totp)
      totp(selectedItem.data.totp)
        .then((v) => {
          if (active) setOtp(v);
        })
        .catch(() => {
          if (active) setOtp("Invalid seed");
        });
    return () => {
      active = false;
    };
  }, [tick, selectedItem]);
  const copy = async (value: string) => {
    await navigator.clipboard.writeText(value);
    notify("Copied. Clear your clipboard after use; browser auto-clear is best effort.");
    setTimeout(() => {
      navigator.clipboard
        .readText()
        .then((current) => {
          if (current === value) return navigator.clipboard.writeText("");
        })
        .catch(() => {});
    }, 30000);
  };
  const save = async (data: Data, entry?: Entry, deleted = false) => {
    const id = entry?.id || crypto.randomUUID(),
      version = entry?.version || 0;
    const payload = await encryptJSON(vaultKey.current!, data, context("item", vaultId.current, id, version + 1));
    await api(`/vaults/${vaultId.current}/items/${id}`, "PUT", {
      expected_version: version,
      payload,
      deleted,
    });
    await sync();
    setSelected(id);
    setEditing(false);
    setDraft(blank());
    notify("Encrypted and synchronized");
  };
  const navigate = (name: string) => {
    setSection(name);
    setMobile(false);
    setSelected(null);
    setEditing(false);
    setShow(false);
    if (name === "Generator") setGenerated(generate(length, symbols).password);
    if (name === "Sharing")
      void run(async () => {
        setShares(await api<Shared[]>("/shares"));
        try {
          const keys = await api<{ public_key: string; private_key: Envelope }>("/sharing/keys");
          setIdentity(keys);
          setOwnFingerprint(await fingerprint(keys.public_key));
        } catch (e) {
          if (!(e instanceof Error) || !e.message.includes("Enable sharing")) throw e;
        }
      });
    if (name === "Devices") void run(async () => setDevices(await api<Device[]>("/devices")));
    if (name === "Security") void run(async () => setEvents(await api<Event[]>("/events")));
    if (name === "Settings")
      void run(async () => {
        const [status, registered] = await Promise.all([
          api<{ enabled: boolean; context: string }>("/account/recovery"),
          api<Passkey[]>("/account/passkeys"),
        ]);
        setRecoveryEnabled(status.enabled);
        setRecoveryContext(status.context);
        setPasskeys(registered);
      });
  };
  const filtered = items.filter((i) => {
    if (i.deleted !== (section === "Trash")) return false;
    const types: Record<string, string> = {
      Passwords: "login",
      "Secure notes": "note",
      Cards: "card",
      Identities: "identity",
      Developer: "api",
    };
    if (section === "Favorites" && !i.data.favorite) return false;
    if (section === "TOTP" && !i.data.totp) return false;
    if (types[section] && i.data.type !== types[section]) return false;
    return [i.data.title, i.data.username, i.data.url, i.data.tags, i.data.folder, labels[i.data.type]].join(" ").toLowerCase().includes(query.toLowerCase());
  });
  const stats = health(items.filter((i) => !i.deleted).map((i) => i.data));
  const download = (value: unknown) => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(value)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "vaultpass-encrypted-backup.json";
    a.click();
    URL.revokeObjectURL(url);
  };
  const backup = async () =>
    run(async () => {
      const snapshot = await sync();
      download({
        format: "vaultpass-backup-v1",
        user_id: session!.user_id,
        bundle: session!.bundle,
        vaults: await api("/vaults"),
        items: snapshot.map(({ data, ...row }) => {
          void data;
          return row;
        }),
      });
      notify("Encrypted backup downloaded. Keep your master password separately.");
    });
  const importFile = async (file: File) =>
    run(async () => {
      if (file.size > 10 * 1024 * 1024) throw new Error("Maximum import size is 10 MB");
      const parsed: unknown = JSON.parse(await file.text());
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && "format" in parsed) {
        const password = window.prompt("Enter the master password used when this encrypted backup was created. Restored items become new copies in this vault.");
        if (!password) return;
        const restored = await restoreBackup(parsed, password);
        for (const data of restored) await save(data);
        notify("Backup restored as new encrypted copies");
        return;
      }
      if (!Array.isArray(parsed) || parsed.length > 500) throw new Error("Import a JSON array of up to 500 items; see import template");
      for (const value of parsed) validateItem(value);
      for (const value of parsed) {
        if (typeof value !== "object" || value === null || typeof value.title !== "string") throw new Error("Every item needs a title");
        const data = validateItem(value);
        await save(data);
      }
      notify("Import complete; plaintext was encrypted locally before upload");
    });
  if (!session)
    return (
      <main className={`auth ${dark ? "dark" : ""}`}>
        <div className="auth-story">
          <div className="brand">
            <ShieldCheck /> VaultPass<span>PRIVATE BY DESIGN</span>
          </div>
          <div>
            <div className="eyebrow">A LITTLE LESS WORRY.</div>
            <h1>
              Your digital life.
              <br />
              <em>Under lock & key.</em>
            </h1>
            <p>A calm, private home for your passwords, notes, and everyday secrets. Encrypted on your device, before they leave it.</p>
            <div className="privacy-pill">
              <LockKeyhole size={18} /> Your master password stays with you.
            </div>
          </div>
          <small>Built for privacy. Designed for everyday life.</small>
        </div>
        <section className="auth-form">
          <div className="auth-card">
            <div className="icon-box">
              <LockKeyhole />
            </div>
            <h2>{mode === "login" ? "Welcome back" : mode === "register" ? "Make room for peace of mind" : "Recover your private space"}</h2>
            <p>{mode === "login" ? "Unlock your private space." : mode === "register" ? "Choose a strong master password you can remember." : "Your recovery key decrypts the account key locally."}</p>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void login();
              }}
            >
              <label>
                Email address
                <input type="email" required autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
              </label>
              {mode === "recover" && (
                <label>
                  Recovery key
                  <input type="password" required autoComplete="off" value={recoveryInput} onChange={(e) => setRecoveryInput(e.target.value)} placeholder="VP1-…" />
                </label>
              )}
              <label>
                {mode === "recover" ? "New master password" : "Master password"}
                <input type="password" minLength={mode === "login" ? 1 : 12} required autoComplete={mode === "login" ? "current-password" : "new-password"} value={master} onChange={(e) => setMaster(e.target.value)} />
              </label>
              {mode === "register" && <p className="warning">There is no server-side password recovery. Enable a recovery key from Settings after registration.</p>}
              {mode === "recover" && <p className="warning">Recovery consumes this key, revokes every session, and requires enrollment of a replacement key.</p>}
              {error && (
                <p role="alert" className="error">
                  {error}
                </p>
              )}
              {notice && <p role="status">{notice}</p>}
              <button className="primary" disabled={busy}>
                {busy ? "Deriving your keys…" : mode === "login" ? "Unlock vault" : mode === "register" ? "Create encrypted vault" : "Recover vault"}
                <LockKeyhole size={16} />
              </button>
            </form>
            <button
              className="text-button"
              onClick={() => {
                setMode(mode === "login" ? "register" : "login");
                setError("");
              }}
            >
              {mode === "login" ? "New here? Create an account" : "Back to sign in"}
            </button>
            {mode === "login" && (
              <button
                className="text-button"
                onClick={() => {
                  setMode("recover");
                  setError("");
                }}
              >
                Use a recovery key
              </button>
            )}
            <small>Argon2id key derivation · AES-256-GCM encryption</small>
          </div>
        </section>
      </main>
    );
  return (
    <main className={`workspace ${dark ? "dark" : ""}`}>
      <aside className={mobile ? "sidebar visible" : "sidebar"}>
        <div className="brand">
          <ShieldCheck /> VaultPass
          <button className="mobile-only icon-button" aria-label="Close navigation" onClick={() => setMobile(false)}>
            <X />
          </button>
        </div>
        <div className="vault-switch">
          <div className="avatar">P</div>
          <div>
            <strong>Personal vault</strong>
            <small>Your private space</small>
          </div>
          <LockKeyhole size={16} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {navigation.map(({ name, icon: Icon }) => (
            <button key={name} className={name === section ? "nav active" : "nav"} onClick={() => navigate(name)}>
              <Icon size={18} />
              {name}
              {name === "All items" && <span className="count">{items.filter((i) => !i.deleted).length}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="private">
            <ShieldCheck size={18} />
            <div>
              Encrypted on your device<small>Only you hold the keys</small>
            </div>
          </div>
          <button className="nav" onClick={lock}>
            <LockKeyhole size={18} />
            Lock vault
          </button>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <button className="icon-button mobile-only" aria-label="Open navigation" onClick={() => setMobile(true)}>
            <Menu />
          </button>
          <span className="breadcrumb">
            Personal vault <span>/</span> <strong>{section}</strong>
          </span>
          <div className="top-actions">
            <span className="status">
              <i /> Vault unlocked
            </span>
            <button className="icon-button" aria-label="Sync vault" disabled={busy} onClick={() => void run(sync)}>
              <RefreshCw size={18} />
            </button>
            <button className="avatar" aria-label="Open settings" onClick={() => navigate("Settings")}>
              {email[0]?.toUpperCase()}
            </button>
          </div>
        </header>
        <div className="content">
          <div className="page-title">
            <div>
              <div className="eyebrow">YOUR PRIVATE SPACE</div>
              <h1>{section}</h1>
              <p>{section === "All items" ? "Everything important. Safely in one place." : "Protected with encryption. Accessible to you."}</p>
            </div>
            <button
              className="primary"
              onClick={() => {
                setSelected(null);
                setDraft(blank());
                setEditing(true);
                setShow(false);
              }}
            >
              <Plus size={18} />
              Add item
            </button>
          </div>
          {error && (
            <div className="error" role="alert">
              {error}
              <button className="text-button" onClick={() => setError("")}>
                Dismiss
              </button>
            </div>
          )}
          {notice && (
            <div className="toast" role="status">
              {notice}
            </div>
          )}
          {section === "Generator" ? (
            <section className="panel tool-panel">
              <div className="icon-box">
                <WandSparkles />
              </div>
              <h2>A stronger password starts here.</h2>
              <p>Generated locally with cryptographically secure randomness.</p>
              <output className="generated">{generated}</output>
              <label>
                Length · {length}
                <input type="range" min="12" max="128" value={length} onChange={(e) => setLength(+e.target.value)} />
              </label>
              <label className="check">
                <input type="checkbox" checked={symbols} onChange={(e) => setSymbols(e.target.checked)} />
                Include symbols
              </label>
              <div className="actions">
                <button className="primary" onClick={() => setGenerated(generate(length, symbols).password)}>
                  Generate password
                </button>
                <button onClick={() => void copy(generated)}>Copy password</button>
              </div>
              <small>Ambiguous characters excluded. Length and random generation help; no strength estimate guarantees security.</small>
            </section>
          ) : section === "Security" ? (
            <>
              <div className="stats">
                <div className="panel">
                  <span>Passwords checked locally</span>
                  <strong>{stats.total}</strong>
                  <small>No vault contents leave this device</small>
                </div>
                <div className="panel">
                  <span>Short passwords</span>
                  <strong>{stats.weak}</strong>
                  <small>Fewer than 14 characters</small>
                </div>
                <div className="panel">
                  <span>Reused passwords</span>
                  <strong>{stats.reused}</strong>
                  <small>Replace each with a unique password</small>
                </div>
              </div>
              <section className="panel">
                <h2>Security activity</h2>
                {events.map((e) => (
                  <div className="event" key={e.id}>
                    <ShieldCheck size={18} />
                    <span>{e.event.replaceAll("_", " ")}</span>
                    <small>{new Date(e.created * 1000).toLocaleString()}</small>
                  </div>
                ))}
              </section>
            </>
          ) : section === "Devices" ? (
            <section className="panel">
              <h2>Your sessions</h2>
              <p>Revoke a session to prevent its next API request.</p>
              {devices.map((d) => (
                <div className="device" key={d.id}>
                  <MonitorSmartphone />
                  <div>
                    <strong>
                      {d.name} {d.current ? "· This device" : ""}
                    </strong>
                    <small>Last active {new Date(d.latest * 1000).toLocaleString()}</small>
                  </div>
                  <button
                    disabled={d.revoked || busy}
                    onClick={() =>
                      void run(async () => {
                        await api(`/devices/${d.id}`, "DELETE");
                        if (d.current) lock();
                        else setDevices(await api("/devices"));
                      })
                    }
                  >
                    {d.revoked ? "Revoked" : "Revoke"}
                  </button>
                </div>
              ))}
            </section>
          ) : section === "Sharing" ? (
            <div className="settings-grid">
              <section className="panel">
                <h2>Your sharing identity</h2>
                <p>Read-only encrypted snapshots. Both accounts must verify their email. Compare fingerprints through a separate trusted channel.</p>
                {identity ? (
                  <>
                    <small>Your public-key fingerprint</small>
                    <p className="secret" style={{ overflowWrap: "anywhere" }}>
                      {ownFingerprint}
                    </p>
                  </>
                ) : (
                  <button
                    disabled={busy}
                    onClick={() =>
                      void run(async () => {
                        const keys = await createIdentity(accountKey.current!, session.user_id);
                        await api("/sharing/keys", "POST", keys);
                        setIdentity(keys);
                        setOwnFingerprint(await fingerprint(keys.public_key));
                      })
                    }
                  >
                    Enable encrypted sharing
                  </button>
                )}
              </section>
              <section className="panel">
                <h2>Share an item</h2>
                <label>
                  Item
                  <select value={sharingItem} onChange={(e) => setSharingItem(e.target.value)}>
                    <option value="">Choose an item</option>
                    {items
                      .filter((i) => !i.deleted)
                      .map((i) => (
                        <option key={i.id} value={i.id}>
                          {i.data.title}
                        </option>
                      ))}
                  </select>
                </label>
                <label>
                  Recipient email
                  <input
                    type="email"
                    value={recipient}
                    onChange={(e) => {
                      setRecipient(e.target.value);
                      setRecipientKey(null);
                      setVerifiedFingerprint(false);
                    }}
                  />
                </label>
                <button
                  onClick={() =>
                    void run(async () => {
                      const key = await api<{
                        user_id: string;
                        public_key: string;
                      }>("/sharing/lookup", "POST", { email: recipient });
                      setRecipientKey({
                        ...key,
                        fingerprint: await fingerprint(key.public_key),
                      });
                      setVerifiedFingerprint(false);
                    })
                  }
                >
                  Find recipient key
                </button>
                {recipientKey && (
                  <>
                    <p className="secret" style={{ overflowWrap: "anywhere" }}>
                      {recipientKey.fingerprint}
                    </p>
                    <label className="check">
                      <input type="checkbox" checked={verifiedFingerprint} onChange={(e) => setVerifiedFingerprint(e.target.checked)} />I compared this fingerprint with the recipient through a trusted channel.
                    </label>
                    <button
                      className="primary"
                      disabled={!verifiedFingerprint || !sharingItem || busy}
                      onClick={() =>
                        void run(async () => {
                          const item = items.find((i) => i.id === sharingItem);
                          if (!item) throw new Error("Choose an item");
                          const share = await encryptShare(item.data, recipientKey.public_key, session.user_id, recipientKey.user_id);
                          await api("/shares", "POST", {
                            ...share,
                            expires: Math.floor(Date.now() / 1000) + 7 * 86400,
                          });
                          setShares(await api("/shares"));
                          notify("Encrypted snapshot shared for 7 days");
                        })
                      }
                    >
                      Share for 7 days
                    </button>
                  </>
                )}
              </section>
              <section className="panel">
                <h2>Shared snapshots</h2>
                <p>Revocation stops future downloads. It cannot erase a copy someone already viewed or saved.</p>
                {shares.map((share) => (
                  <div className="note" key={share.id}>
                    <strong>{share.outgoing ? "Sent snapshot" : "Received snapshot"}</strong>
                    <small>{share.revoked ? "Revoked" : `Expires ${new Date(share.expires * 1000).toLocaleString()}`}</small>
                    {share.data && (
                      <>
                        <h3>{share.data.title}</h3>
                        <pre
                          style={{
                            whiteSpace: "pre-wrap",
                            overflowWrap: "anywhere",
                          }}
                        >
                          {JSON.stringify(share.data, null, 2)}
                        </pre>
                        <button onClick={() => void run(() => save(share.data!))}>Save a personal copy</button>
                      </>
                    )}
                    {share.outgoing ? (
                      <button
                        disabled={share.revoked}
                        onClick={() =>
                          void run(async () => {
                            await api(`/shares/${share.id}`, "DELETE");
                            setShares(await api("/shares"));
                          })
                        }
                      >
                        Revoke
                      </button>
                    ) : (
                      <button
                        disabled={!identity || !share.payload}
                        onClick={() =>
                          void run(async () => {
                            if (!share.payload || !share.wrapped_key || !identity) return;
                            const data = await decryptShare<Data>(
                              {
                                ...share,
                                payload: share.payload,
                                wrapped_key: share.wrapped_key,
                              },
                              accountKey.current!,
                              identity.private_key,
                            );
                            setShares((prev) => prev.map((s) => (s.id === share.id ? { ...s, data } : s)));
                          })
                        }
                      >
                        Decrypt snapshot
                      </button>
                    )}
                  </div>
                ))}
              </section>
            </div>
          ) : section === "Settings" ? (
            <div className="settings-grid">
              <section className="panel">
                <h2>Preferences</h2>
                <label className="check">
                  <input type="checkbox" checked={dark} onChange={(e) => setDark(e.target.checked)} />
                  Dark appearance
                </label>
                <p>Vault locks after 5 minutes of inactivity and immediately when this tab is hidden. Signing in is required again.</p>
                <button
                  onClick={() =>
                    void run(async () => {
                      await api("/auth/logout", "POST");
                      lock();
                    })
                  }
                >
                  <LogOut size={16} />
                  Sign out
                </button>
              </section>
              <section className="panel">
                <h2>Recovery key</h2>
                <p>{recoveryEnabled ? "A recovery key is enrolled. It is never sent to VaultPass and will be consumed after recovery." : "Create a one-time recovery key that wraps your account key locally."}</p>
                {shownRecovery ? (
                  <>
                    <p className="warning">Save this key now. It cannot be shown again.</p>
                    <output className="secret" style={{ overflowWrap: "anywhere" }}>
                      {shownRecovery}
                    </output>
                    <div className="actions">
                      <button onClick={() => void copy(shownRecovery)}>Copy recovery key</button>
                      <button onClick={() => setShownRecovery("")}>I saved it</button>
                    </div>
                  </>
                ) : (
                  <>
                    <label>
                      Current master password
                      <input type="password" value={authConfirm} onChange={(e) => setAuthConfirm(e.target.value)} />
                    </label>
                    {recoveryEnabled ? (
                      <button
                        disabled={busy || !authConfirm}
                        onClick={() =>
                          void run(async () => {
                            const d = await derive(authConfirm, session.bundle.salt);
                            try {
                              await api("/account/recovery", "DELETE", {
                                auth_secret: d.auth,
                              });
                              setRecoveryEnabled(false);
                              setAuthConfirm("");
                              notify("Recovery key disabled");
                            } finally {
                              d.wrap.fill(0);
                            }
                          })
                        }
                      >
                        Disable recovery key
                      </button>
                    ) : (
                      <button
                        disabled={busy || !authConfirm}
                        onClick={() =>
                          void run(async () => {
                            const d = await derive(authConfirm, session.bundle.salt);
                            try {
                              const recovery = await createRecovery(accountKey.current!, recoveryContext);
                              await api("/account/recovery", "POST", {
                                current_auth_secret: d.auth,
                                recovery_auth_secret: recovery.recoveryAuth,
                                account_key: recovery.accountKey,
                              });
                              setShownRecovery(recovery.recoveryKey);
                              setRecoveryEnabled(true);
                              setAuthConfirm("");
                            } finally {
                              d.wrap.fill(0);
                            }
                          })
                        }
                      >
                        Create recovery key
                      </button>
                    )}
                  </>
                )}
              </section>
              <section className="panel">
                <h2>Passkey MFA</h2>
                <p>
                  Require a passkey after your master password before VaultPass issues a session.
                  Your passkey does not decrypt the vault and no TOTP seed is stored by the server.
                </p>
                {passkeys.map((passkey) => (
                  <div className="device" key={passkey.id}>
                    <KeyRound />
                    <div>
                      <strong>{passkey.name}</strong>
                      <small>
                        {passkey.backed_up ? "Synced passkey" : "Device-bound passkey"} · Last used {new Date(passkey.latest * 1000).toLocaleString()}
                      </small>
                    </div>
                    <button
                      disabled={busy || !passkeyMaster}
                      onClick={() =>
                        void run(async () => {
                          const d = await derive(passkeyMaster, session.bundle.salt);
                          try {
                            await api(`/account/passkeys/${encodeURIComponent(passkey.id)}`, "DELETE", {
                              auth_secret: d.auth,
                            });
                            setPasskeys(await api<Passkey[]>("/account/passkeys"));
                            setPasskeyMaster("");
                            notify("Passkey removed");
                          } finally {
                            d.wrap.fill(0);
                          }
                        })
                      }
                    >
                      Remove
                    </button>
                  </div>
                ))}
                <label>
                  Passkey name
                  <input maxLength={80} value={passkeyName} onChange={(e) => setPasskeyName(e.target.value)} />
                </label>
                <label>
                  Master password for passkeys
                  <input type="password" value={passkeyMaster} onChange={(e) => setPasskeyMaster(e.target.value)} />
                </label>
                <button
                  disabled={busy || !passkeyMaster || !passkeyName.trim()}
                  onClick={() =>
                    void run(async () => {
                      const d = await derive(passkeyMaster, session.bundle.salt);
                      try {
                        const enrollment = await api<{
                          token: string;
                          public_key: RegistrationOptions;
                        }>("/account/passkeys/options", "POST", {
                          current_auth_secret: d.auth,
                          name: passkeyName.trim(),
                        });
                        const credential = await createPasskey(enrollment.public_key);
                        await api("/account/passkeys", "POST", {
                          token: enrollment.token,
                          credential,
                        });
                        setPasskeys(await api<Passkey[]>("/account/passkeys"));
                        setPasskeyMaster("");
                        notify("Passkey MFA enabled");
                      } finally {
                        d.wrap.fill(0);
                      }
                    })
                  }
                >
                  Add passkey
                </button>
                {passkeys.length === 1 && (
                  <p className="warning">Add another passkey or keep your recovery key available before relying on this authenticator.</p>
                )}
              </section>
              <section className="panel">
                <h2>Backup & import</h2>
                <p>Backups contain ciphertext and wrapped keys. JSON imports and restored backups are encrypted locally. Restoring creates new copies.</p>
                <div className="actions">
                  <button onClick={() => void backup()}>
                    <Download size={16} />
                    Encrypted backup
                  </button>
                  <label className="file-button">
                    <Upload size={16} />
                    Import / restore
                    <input
                      type="file"
                      accept="application/json"
                      onChange={(e) => {
                        if (e.target.files?.[0]) void importFile(e.target.files[0]);
                        e.target.value = "";
                      }}
                    />
                  </label>
                </div>
              </section>
              <section className="panel">
                <h2>Change master password</h2>
                <label>
                  Current password
                  <input type="password" value={authConfirm} onChange={(e) => setAuthConfirm(e.target.value)} />
                </label>
                <label>
                  New password
                  <input type="password" minLength={12} value={newMaster} onChange={(e) => setNewMaster(e.target.value)} />
                </label>
                <button
                  disabled={busy}
                  onClick={() =>
                    void run(async () => {
                      const d = await derive(authConfirm, session.bundle.salt);
                      try {
                        const update = await rewrap(newMaster, session.user_id, accountKey.current!);
                        await api("/account/password", "POST", {
                          current_auth_secret: d.auth,
                          ...update,
                        });
                        lock();
                      } finally {
                        d.wrap.fill(0);
                      }
                    })
                  }
                >
                  Change password & revoke sessions
                </button>
              </section>
              <section className="panel">
                <h2>Email verification</h2>
                <button
                  onClick={() =>
                    void run(async () => {
                      await api("/account/verification", "POST");
                      notify("Check your email for a verification token");
                    })
                  }
                >
                  Send verification email
                </button>
                <label>
                  Verification token
                  <input value={verifyToken} onChange={(e) => setVerifyToken(e.target.value)} />
                </label>
                <button
                  onClick={() =>
                    void run(async () => {
                      await api("/auth/verify", "POST", { token: verifyToken });
                      setVerifyToken("");
                      notify("Email verified");
                    })
                  }
                >
                  Verify
                </button>
              </section>
              <section className="panel danger">
                <h2>Delete account</h2>
                <p>Deletes this account and its encrypted vault. Backups are your responsibility.</p>
                <label>
                  Master password
                  <input type="password" value={authConfirm} onChange={(e) => setAuthConfirm(e.target.value)} />
                </label>
                <button
                  onClick={() => {
                    if (window.confirm("Permanently delete your account and encrypted vault?"))
                      void run(async () => {
                        const d = await derive(authConfirm, session.bundle.salt);
                        try {
                          await api("/account/delete", "POST", {
                            auth_secret: d.auth,
                          });
                          lock();
                        } finally {
                          d.wrap.fill(0);
                        }
                      });
                  }}
                >
                  Permanently delete account
                </button>
              </section>
            </div>
          ) : (
            <>
              <div className="summary-strip">
                <div>
                  <ShieldCheck size={20} />
                  <strong>{items.filter((i) => !i.deleted).length}</strong>
                  <span>protected items</span>
                </div>
                <div>
                  <Star size={20} />
                  <strong>{items.filter((i) => i.data.favorite && !i.deleted).length}</strong>
                  <span>favorites</span>
                </div>
                <span className="local-badge">Search stays on your device</span>
              </div>
              <div className="vault-layout">
                <section className="panel item-list">
                  <div className="search">
                    <Search size={18} />
                    <input aria-label="Search vault" placeholder="Search your vault…" value={query} onChange={(e) => setQuery(e.target.value)} />
                    <span>{filtered.length} items</span>
                  </div>
                  <div className="list-heading">
                    <span>NAME</span>
                    <span>LAST UPDATED</span>
                  </div>
                  {filtered.length ? (
                    filtered.map((item) => (
                      <button
                        key={item.id}
                        className={`item ${selected === item.id ? "selected" : ""}`}
                        onClick={() => {
                          setSelected(item.id);
                          setEditing(false);
                          setShow(false);
                          setHistory([]);
                        }}
                      >
                        <div className={`item-icon ${item.data.type}`}>{item.data.type === "note" ? <FileText /> : item.data.type === "card" ? <CreditCard /> : <KeyRound />}</div>
                        <div>
                          <strong>{item.data.title}</strong>
                          <small>
                            {item.data.username || labels[item.data.type]}
                            {item.data.folder ? ` · ${item.data.folder}` : ""}
                          </small>
                        </div>
                        {item.data.favorite && <Star size={14} />}
                        <time>{new Date(item.updated * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric" })}</time>
                      </button>
                    ))
                  ) : (
                    <div className="empty">
                      <div className="icon-box">
                        <LockKeyhole />
                      </div>
                      <h2>{query ? "No matching items" : "Your private space is ready"}</h2>
                      <p>{query ? "Try a title, username, tag, or folder." : "Add your first password, note, or secret. We’ll encrypt it before syncing."}</p>
                      <button
                        className="primary"
                        onClick={() => {
                          setSelected(null);
                          setDraft(blank());
                          setEditing(true);
                        }}
