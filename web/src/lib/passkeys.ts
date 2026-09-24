type EncodedDescriptor = Omit<PublicKeyCredentialDescriptor, "id"> & { id: string };

export type RegistrationOptions = Omit<
  PublicKeyCredentialCreationOptions,
  "challenge" | "user" | "excludeCredentials"
> & {
  challenge: string;
  user: Omit<PublicKeyCredentialUserEntity, "id"> & { id: string };
  excludeCredentials?: EncodedDescriptor[];
};

export type AuthenticationOptions = Omit<
  PublicKeyCredentialRequestOptions,
  "challenge" | "allowCredentials"
> & {
  challenge: string;
  allowCredentials?: EncodedDescriptor[];
};

export type SerializedCredential = {
  id: string;
  rawId: string;
  type: "public-key";
  authenticatorAttachment?: string;
  response: Record<string, string | string[] | null>;
};

function decode(value: string): ArrayBuffer {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function encode(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function supported(): void {
  if (!window.isSecureContext || !navigator.credentials || !window.PublicKeyCredential)
    throw new Error("Passkeys require a supported browser and a secure HTTPS connection.");
}

export async function createPasskey(options: RegistrationOptions): Promise<SerializedCredential> {
  supported();
  const credential = (await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: decode(options.challenge),
      user: { ...options.user, id: decode(options.user.id) },
      excludeCredentials: options.excludeCredentials?.map((item) => ({
        ...item,
        id: decode(item.id),
      })),
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Passkey enrollment was cancelled.");
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: "public-key",
    ...(credential.authenticatorAttachment
      ? { authenticatorAttachment: credential.authenticatorAttachment }
      : {}),
    response: {
      clientDataJSON: encode(response.clientDataJSON),
      attestationObject: encode(response.attestationObject),
      transports: response.getTransports?.() || [],
    },
  };
}

export async function authenticatePasskey(
  options: AuthenticationOptions,
): Promise<SerializedCredential> {
  supported();
  const credential = (await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: decode(options.challenge),
      allowCredentials: options.allowCredentials?.map((item) => ({
        ...item,
        id: decode(item.id),
      })),
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Passkey verification was cancelled.");
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: encode(credential.rawId),
    type: "public-key",
    ...(credential.authenticatorAttachment
      ? { authenticatorAttachment: credential.authenticatorAttachment }
      : {}),
    response: {
      clientDataJSON: encode(response.clientDataJSON),
      authenticatorData: encode(response.authenticatorData),
      signature: encode(response.signature),
      userHandle: response.userHandle ? encode(response.userHandle) : null,
    },
  };
}
