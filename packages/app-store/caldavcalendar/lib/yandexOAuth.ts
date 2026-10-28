import { symmetricDecrypt, symmetricEncrypt } from "@calcom/lib/crypto";
import { ErrorWithCode } from "@calcom/lib/errors";
import prisma from "@calcom/prisma";
import { credentialForCalendarServiceSelect } from "@calcom/prisma/selects/credential";
import type { CredentialPayload } from "@calcom/types/Credential";
import { z } from "zod";

const pending = new Map<number, Promise<CredentialPayload>>();
const tokenSchema = z.object({
  access_token: z.string().min(1),
  refresh_token: z.string().min(1),
  expires_in: z.number().positive(),
});

export function isYandexCredential(credential: Pick<CredentialPayload, "key">, yandexUserId?: string) {
  if (typeof credential.key !== "string") return false;
  const key = JSON.parse(symmetricDecrypt(credential.key, process.env.CALENDSO_ENCRYPTION_KEY || ""));
  return key.oauthProvider === "yandex" && (!yandexUserId || key.yandexUserId === yandexUserId);
}

export async function findYandexCalendarCredential(userId: number, yandexUserId?: string) {
  const credentials = await prisma.credential.findMany({
    where: { userId, appId: "caldav-calendar" },
    select: credentialForCalendarServiceSelect,
  });
  const credential = credentials.find((candidate) => isYandexCredential(candidate, yandexUserId));
  if (!credential) throw ErrorWithCode.Factory.Unauthorized("Connect the corporate Yandex calendar");
  return credential;
}

export async function refreshYandexCalendarCredential(
  credential: CredentialPayload
): Promise<CredentialPayload> {
  const running = pending.get(credential.id);
  if (running) return running;
  const refresh = async () => {
    const stored = await prisma.credential.findUniqueOrThrow({
      where: { id: credential.id },
      select: { key: true },
    });
    const encryptionKey = process.env.CALENDSO_ENCRYPTION_KEY || "";
    const key = JSON.parse(symmetricDecrypt(stored.key as string, encryptionKey));
    if (key.oauthProvider !== "yandex" || key.expiresAt > Date.now() / 1000 + 120) {
      return { ...credential, key: stored.key };
    }
    const response = await fetch("https://oauth.yandex.ru/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: key.refreshToken,
        client_id: process.env.YANDEX_CLIENT_ID || "",
        client_secret: process.env.YANDEX_CLIENT_SECRET || "",
      }),
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) throw ErrorWithCode.Factory.Unauthorized("Yandex calendar reconnection required");
    const token = tokenSchema.parse(await response.json());
    const encrypted = symmetricEncrypt(
      JSON.stringify({
        ...key,
        password: token.access_token,
        refreshToken: token.refresh_token,
        expiresAt: Date.now() / 1000 + token.expires_in,
      }),
      encryptionKey
    );
    await prisma.credential.update({
      where: { id: credential.id },
      data: { key: encrypted, invalid: false },
    });
    return { ...credential, key: encrypted };
  };
  const result = refresh();
  pending.set(credential.id, result);
  try {
    return await result;
  } finally {
    pending.delete(credential.id);
  }
}
