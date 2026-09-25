"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../lib/api";
import { bytes, Envelope } from "../lib/crypto";
import { fingerprint } from "../lib/sharing";
import {
  createTeamKey,
  decryptTeamItem,
  encryptTeamItem,
  unwrapTeamKey,
  wrapTeamKey,
} from "../lib/teams";

type Team = {
  id: string;
  name: string;
  owner_id: string;
  role: "owner" | "admin" | "member" | "read_only";
  key_version: number;
  wrapped_key: string;
  created: number;
};

type Member = {
  user_id: string;
  email: string;
  role: Team["role"];
  public_key: string | null;
  key_version: number;
  joined: number;
};

type Invitation = {
  id: string;
  recipient_id: string;
  role: "admin" | "member" | "read_only";
  key_version: number;
  expires: number;
  revoked: boolean;
  accepted: boolean;
  created: number;
};

type IncomingInvitation = {
  id: string;
  team_id: string;
  team_name: string;
  inviter_id: string;
  role: "admin" | "member" | "read_only";
  wrapped_key: string;
  key_version: number;
  expires: number;
};

type SharingIdentity = { public_key: string; private_key: Envelope };

type TeamItemData = {
  title: string;
  username: string;
  password: string;
  notes: string;
};

type TeamRow = {
  id: string;
  version: number;
  payload: Envelope;
  deleted: boolean;
  purged: boolean;
  updated: number;
  data: TeamItemData;
};

const emptyItem = (): TeamItemData => ({
  title: "",
  username: "",
  password: "",
  notes: "",
});

export function TeamsPanel({
  accountKey,
  userId,
  notify,
}: {
  accountKey: Uint8Array;
  userId: string;
  notify: (message: string) => void;
}) {
  const teamKey = useRef<Uint8Array | null>(null);
  const [teams, setTeams] = useState<Team[]>([]);
  const [incoming, setIncoming] = useState<IncomingInvitation[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [members, setMembers] = useState<Member[]>([]);
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [rows, setRows] = useState<TeamRow[]>([]);
  const [identity, setIdentity] = useState<SharingIdentity | null>(null);
  const [teamName, setTeamName] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"admin" | "member" | "read_only">("member");
  const [candidate, setCandidate] = useState<{ user_id: string; public_key: string; fingerprint: string } | null>(null);
  const [verifiedFingerprint, setVerifiedFingerprint] = useState(false);
  const [editing, setEditing] = useState<TeamRow | null>(null);
  const [draft, setDraft] = useState<TeamItemData>(emptyItem());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [rekeyProgress, setRekeyProgress] = useState("");

  const selected = teams.find((team) => team.id === selectedId) ?? null;

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (value) {
      setError(value instanceof Error ? value.message : "Team operation failed");
    } finally {
      setBusy(false);
    }
  };

  const loadOverview = useCallback(async () => {
    const [teamRows, invitationRows] = await Promise.all([
      api<Team[]>("/teams"),
      api<IncomingInvitation[]>("/team-invitations"),
    ]);
    setTeams(teamRows);
    setIncoming(invitationRows);
    try {
      setIdentity(await api<SharingIdentity>("/sharing/keys"));
    } catch (value) {
      if (value instanceof ApiError && (value.status === 404 || value.status === 409)) {
        setIdentity(null);
      } else {
        throw value;
      }
    }
  }, []);

  const openTeam = useCallback(
    async (team: Team, knownIdentity?: SharingIdentity | null) => {
      const sharing = knownIdentity ?? identity ?? (await api<SharingIdentity>("/sharing/keys"));
      const nextKey = await unwrapTeamKey(
        team.wrapped_key,
        accountKey,
        sharing.private_key,
        team.id,
        userId,
        team.key_version,
      );
      teamKey.current?.fill(0);
      teamKey.current = nextKey;
      setSelectedId(team.id);

      const [memberRows, invitationRows] = await Promise.all([
        api<Member[]>(`/teams/${team.id}/members`),
        team.role === "owner" || team.role === "admin"
          ? api<Invitation[]>(`/teams/${team.id}/invitations`)
          : Promise.resolve([]),
      ]);
      setMembers(memberRows);
      setInvitations(invitationRows);

      const encrypted: Omit<TeamRow, "data">[] = [];
      let cursor = 0;
      let more = true;
      while (more) {
        const page = await api<{
          cursor: number;
          has_more: boolean;
          key_version: number;
          items: Omit<TeamRow, "data">[];
        }>(`/teams/${team.id}/sync?after=${cursor}`);
        if (page.key_version !== team.key_version) {
          throw new Error("Team key changed. Refresh the team before decrypting.");
        }
        encrypted.push(...page.items);
        cursor = page.cursor;
        more = page.has_more;
      }
      const decrypted: TeamRow[] = [];
      for (const row of encrypted) {
        if (row.purged) continue;
        decrypted.push({
          ...row,
          data: await decryptTeamItem<TeamItemData>(
            nextKey,
            row.payload,
            team.id,
            row.id,
            team.key_version,
            row.version,
          ),
        });
      }
      setRows(decrypted.sort((a, b) => b.updated - a.updated));
    },
    [accountKey, identity, userId],
  );

  useEffect(() => {
    void run(loadOverview);
    return () => {
      teamKey.current?.fill(0);
      teamKey.current = null;
    };
  }, [loadOverview]);

  const refreshSelected = async () => {
    const latest = await api<Team[]>("/teams");
    setTeams(latest);
    setIncoming(await api<IncomingInvitation[]>("/team-invitations"));
    const team = latest.find((value) => value.id === selectedId);
    if (team) await openTeam(team);
    else {
      teamKey.current?.fill(0);
      teamKey.current = null;
      setSelectedId("");
      setMembers([]);
      setInvitations([]);
      setRows([]);
    }
  };

  const saveItem = async () => {
    if (!selected || !teamKey.current) throw new Error("Open a team vault first");
    if (selected.role === "read_only") throw new Error("Read-only members cannot edit");
    const id = editing?.id ?? crypto.randomUUID();
    const expectedVersion = editing?.version ?? 0;
    const payload = await encryptTeamItem(
      teamKey.current,
      draft,
      selected.id,
      id,
      selected.key_version,
      expectedVersion + 1,
    );
    await api(`/teams/${selected.id}/items/${id}`, "PUT", {
      expected_key_version: selected.key_version,
      expected_version: expectedVersion,
      payload,
      deleted: editing?.deleted ?? false,
    });
    setEditing(null);
    setDraft(emptyItem());
    await openTeam(selected);
    notify("Team item encrypted and synchronized");
  };

  const secureRemoveMember = async (target: Member) => {
    if (!selected || !teamKey.current) throw new Error("Open a team vault first");
    if (!(selected.role === "owner" || selected.role === "admin")) throw new Error("Administrator access required");
    if (target.role === "owner") throw new Error("Transfer ownership before removing the owner");
    if (selected.role !== "owner" && target.role === "admin") throw new Error("Only the owner can remove administrators");
    if (!window.confirm(`Remove ${target.email}? VaultPass will rotate the team key and re-encrypt retained ciphertext before access is removed.`)) return;

    const rotationId = crypto.randomUUID();
    const newKey = bytes(32);
    try {
      const started = await api<{ new_key_version: number }>(`/teams/${selected.id}/rotations`, "POST", {
        id: rotationId,
        target_id: target.user_id,
        expected_key_version: selected.key_version,
      });
      const remaining = members.filter((member) => member.user_id !== target.user_id);
      setRekeyProgress(`Wrapping fresh key for 0/${remaining.length} members`);
      for (let index = 0; index < remaining.length; index += 1) {
        const member = remaining[index];
        if (!member.public_key) throw new Error(`${member.email} has no sharing key`);
        const wrapped_key = await wrapTeamKey(
          newKey,
          member.public_key,
          selected.id,
          member.user_id,
          started.new_key_version,
        );
        await api(`/teams/${selected.id}/rotations/${rotationId}/members/${member.user_id}`, "PUT", {
          wrapped_key,
        });
        setRekeyProgress(`Wrapping fresh key for ${index + 1}/${remaining.length} members`);
      }

      const retained = rows.filter((row) => !row.purged);
      setRekeyProgress(`Re-encrypting 0/${retained.length} retained items`);
      for (let index = 0; index < retained.length; index += 1) {
        const row = retained[index];
        const payload = await encryptTeamItem(
          newKey,
          row.data,
          selected.id,
          row.id,
          started.new_key_version,
          row.version + 1,
        );
        await api(`/teams/${selected.id}/rotations/${rotationId}/items/${row.id}`, "PUT", {
          expected_version: row.version,
          payload,
        });
        setRekeyProgress(`Re-encrypting ${index + 1}/${retained.length} retained items`);
      }
      setRekeyProgress("Finalizing atomic key rotation");
      await api(`/teams/${selected.id}/rotations/${rotationId}/finalize`, "POST");
      setRekeyProgress("");
      await refreshSelected();
      notify("Member removed after atomic team-key rotation");
    } catch (value) {
      await api(`/teams/${selected.id}/rotations/${rotationId}`, "DELETE").catch(() => undefined);
      setRekeyProgress("");
      throw value;
    } finally {
      newKey.fill(0);
    }
  };

  return (
    <div className="settings-grid">
      {error && <div className="error" role="alert">{error}</div>}
      <section className="panel">
        <h2>Team vaults</h2>
        <p>Team keys and item plaintext stay on this device. The server receives wrappers and ciphertext only.</p>
        {!identity && <p className="warning">Enable encrypted sharing first. A sharing keypair is required to wrap team keys for members.</p>}
        <label>
          New team name
          <input maxLength={80} value={teamName} onChange={(event) => setTeamName(event.target.value)} />
        </label>
        <button
          className="primary"
          disabled={busy || !identity || !teamName.trim()}
          onClick={() => void run(async () => {
            if (!identity) throw new Error("Enable encrypted sharing first");
            const id = crypto.randomUUID();
            const created = await createTeamKey(identity.public_key, id, userId);
            try {
              await api("/teams", "POST", { id, name: teamName.trim(), wrapped_key: created.wrappedKey });
            } finally {
              created.key.fill(0);
            }
            setTeamName("");
            await loadOverview();
            notify("Team vault created");
          })}
        >
          Create team vault
        </button>
        <div className="actions">
          {teams.map((team) => (
            <button
              key={team.id}
              className={team.id === selectedId ? "primary" : ""}
              disabled={busy || !identity}
              onClick={() => void run(() => openTeam(team))}
            >
              {team.name} · {team.role.replace("_", " ")}
            </button>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2>Incoming invitations</h2>
        {incoming.length === 0 && <p>No pending invitations.</p>}
        {incoming.map((invitation) => (
          <div className="device" key={invitation.id}>
            <div>
              <strong>{invitation.team_name}</strong>
              <small>{invitation.role.replace("_", " ")} · expires {new Date(invitation.expires * 1000).toLocaleString()}</small>
            </div>
            <div className="actions">
              <button disabled={busy} onClick={() => void run(async () => {
                await api(`/team-invitations/${invitation.id}/accept`, "POST");
                await loadOverview();
                notify("Team invitation accepted");
              })}>Accept</button>
              <button disabled={busy} onClick={() => void run(async () => {
                await api(`/team-invitations/${invitation.id}/decline`, "POST");
                await loadOverview();
                notify("Team invitation declined");
              })}>Decline</button>
            </div>
          </div>
        ))}
      </section>

      {selected && teamKey.current && (
        <>
          <section className="panel">
            <h2>{selected.name}</h2>
            <p>Key epoch {selected.key_version} · role {selected.role.replace("_", " ")}</p>
            {selected.role !== "read_only" && (
              <>
                <label>
                  Title
                  <input value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} />
                </label>
                <label>
                  Username
                  <input value={draft.username} onChange={(event) => setDraft({ ...draft, username: event.target.value })} />
                </label>
                <label>
                  Password / secret
                  <input type="password" value={draft.password} onChange={(event) => setDraft({ ...draft, password: event.target.value })} />
                </label>
                <label>
                  Notes
                  <textarea value={draft.notes} onChange={(event) => setDraft({ ...draft, notes: event.target.value })} />
                </label>
                <div className="actions">
                  <button className="primary" disabled={busy || !draft.title.trim()} onClick={() => void run(saveItem)}>
                    {editing ? "Save encrypted changes" : "Add encrypted team item"}
                  </button>
                  {editing && <button onClick={() => { setEditing(null); setDraft(emptyItem()); }}>Cancel</button>}
                </div>
              </>
            )}
            {rows.filter((row) => !row.deleted).map((row) => (
              <div className="note" key={row.id}>
                <strong>{row.data.title || "Untitled"}</strong>
                <small>Encrypted revision {row.version}</small>
                <p>{row.data.username}</p>
                <div className="actions">
                  <button onClick={() => { setEditing(row); setDraft(row.data); }}>Edit</button>
                  {selected.role !== "read_only" && (
                    <button disabled={busy} onClick={() => void run(async () => {
                      const payload = await encryptTeamItem(
                        teamKey.current!,
                        row.data,
                        selected.id,
                        row.id,
                        selected.key_version,
                        row.version + 1,
                      );
                      await api(`/teams/${selected.id}/items/${row.id}`, "PUT", {
                        expected_key_version: selected.key_version,
                        expected_version: row.version,
                        payload,
                        deleted: true,
                      });
                      await openTeam(selected);
                    })}>Move to trash</button>
                  )}
                </div>
              </div>
            ))}
          </section>

          <section className="panel">
            <h2>Members</h2>
            {rekeyProgress && <p className="warning">{rekeyProgress}. Do not close this tab.</p>}
            {members.map((member) => (
              <div className="device" key={member.user_id}>
                <div>
                  <strong>{member.email}{member.user_id === userId ? " · You" : ""}</strong>
                  <small>{member.role.replace("_", " ")}</small>
                </div>
                <div className="actions">
                  {(selected.role === "owner" || selected.role === "admin") && member.role !== "owner" && (
                    <select
                      aria-label={`Role for ${member.email}`}
                      value={member.role}
                      disabled={busy || (selected.role !== "owner" && member.role === "admin")}
                      onChange={(event) => void run(async () => {
                        await api(`/teams/${selected.id}/members/${member.user_id}`, "PATCH", { role: event.target.value });
                        await openTeam(selected);
                      })}
                    >
                      {selected.role === "owner" && <option value="admin">Admin</option>}
                      <option value="member">Member</option>
                      <option value="read_only">Read only</option>
                    </select>
                  )}
                  {selected.role === "owner" && member.user_id !== userId && (
                    <button disabled={busy} onClick={() => void run(async () => {
                      if (!window.confirm(`Transfer ownership to ${member.email}?`)) return;
                      await api(`/teams/${selected.id}/transfer-ownership`, "POST", { target_id: member.user_id });
                      await refreshSelected();
                      notify("Team ownership transferred");
                    })}>Transfer ownership</button>
                  )}
                  {(selected.role === "owner" || selected.role === "admin") && member.user_id !== userId && member.role !== "owner" && (
                    <button disabled={busy} onClick={() => void run(() => secureRemoveMember(member))}>Remove securely</button>
                  )}
                </div>
              </div>
            ))}
            {selected.role !== "owner" && (
              <p className="warning">Self-leave is intentionally unavailable until a reviewed protocol can rotate the key without giving a departing member unilateral ciphertext-replacement authority. Ask an owner/admin to remove you securely.</p>
            )}
          </section>

          {(selected.role === "owner" || selected.role === "admin") && (
            <section className="panel">
              <h2>Invite member</h2>
              <label>
                Recipient email
                <input type="email" value={inviteEmail} onChange={(event) => {
                  setInviteEmail(event.target.value);
                  setCandidate(null);
                  setVerifiedFingerprint(false);
                }} />
              </label>
              <label>
                Role
                <select value={inviteRole} onChange={(event) => setInviteRole(event.target.value as "admin" | "member" | "read_only")}>
                  {selected.role === "owner" && <option value="admin">Admin</option>}
                  <option value="member">Member</option>
                  <option value="read_only">Read only</option>
                </select>
              </label>
              <button disabled={busy || !inviteEmail} onClick={() => void run(async () => {
                const key = await api<{ user_id: string; public_key: string }>("/sharing/lookup", "POST", { email: inviteEmail });
                setCandidate({ ...key, fingerprint: await fingerprint(key.public_key) });
                setVerifiedFingerprint(false);
              })}>Find recipient key</button>
              {candidate && (
                <>
                  <p className="secret" style={{ overflowWrap: "anywhere" }}>{candidate.fingerprint}</p>
                  <label className="check">
                    <input type="checkbox" checked={verifiedFingerprint} onChange={(event) => setVerifiedFingerprint(event.target.checked)} />
                    I compared this fingerprint with the recipient through a trusted channel.
                  </label>
                  <button className="primary" disabled={busy || !verifiedFingerprint} onClick={() => void run(async () => {
                    const wrapped_key = await wrapTeamKey(
                      teamKey.current!,
                      candidate.public_key,
                      selected.id,
                      candidate.user_id,
                      selected.key_version,
                    );
                    await api(`/teams/${selected.id}/invitations`, "POST", {
                      id: crypto.randomUUID(),
                      recipient_id: candidate.user_id,
                      role: inviteRole,
                      wrapped_key,
                      expected_key_version: selected.key_version,
                      expires: Math.floor(Date.now() / 1000) + 7 * 86400,
                    });
                    setInviteEmail("");
                    setCandidate(null);
                    setVerifiedFingerprint(false);
                    await openTeam(selected);
                    notify("Encrypted team invitation created");
                  })}>Invite for 7 days</button>
                </>
              )}
              {invitations.filter((value) => !value.accepted && !value.revoked).map((invitation) => (
                <div className="device" key={invitation.id}>
                  <div>
                    <strong>Pending member</strong>
                    <small>{invitation.role.replace("_", " ")} · expires {new Date(invitation.expires * 1000).toLocaleString()}</small>
                  </div>
                  <button disabled={busy} onClick={() => void run(async () => {
                    await api(`/teams/${selected.id}/invitations/${invitation.id}`, "DELETE");
                    await openTeam(selected);
                  })}>Revoke invitation</button>
                </div>
              ))}
            </section>
          )}

          {selected.role === "owner" && (
            <section className="panel">
              <h2>Danger zone</h2>
              <p>Deleting a team removes server-side ciphertext and membership metadata. Previously copied plaintext/ciphertext cannot be remotely erased.</p>
              <button disabled={busy} onClick={() => void run(async () => {
                if (!window.confirm(`Delete ${selected.name}? This cannot be undone.`)) return;
                await api(`/teams/${selected.id}`, "DELETE");
                await loadOverview();
                setSelectedId("");
                setRows([]);
                setMembers([]);
                teamKey.current?.fill(0);
                teamKey.current = null;
                notify("Team vault deleted");
              })}>Delete team vault</button>
            </section>
          )}
        </>
      )}
    </div>
  );
}
