import { symmetricDecrypt, symmetricEncrypt } from "@calcom/lib/crypto";
import prisma from "@calcom/prisma";
import type { CredentialPayload } from "@calcom/types/Credential";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { findYandexCalendarCredential, refreshYandexCalendarCredential } from "./yandexOAuth";

vi.mock("@calcom/prisma", () => ({
  default: { credential: { findUniqueOrThrow: vi.fn(), findMany: vi.fn(), update: vi.fn() } },
}));

describe("Yandex calendar token refresh", () => {
  const secret = "00000000000000000000000000000000";
  const credential: CredentialPayload = {
    id: 1,
    type: "caldav_calendar",
    appId: "caldav-calendar",
    userId: 1,
    teamId: null,
    user: { email: "employee@effective.band" },
    key: "",
    encryptedKey: null,
    invalid: false,
    delegationCredentialId: null,
  };
  const stored = (expiresAt: number) =>
    symmetricEncrypt(
      JSON.stringify({
        username: "employee@effective.band",
        password: "test-old-access",
        oauthProvider: "yandex",
        url: "https://caldav.yandex.ru",
        refreshToken: "test-old-refresh",
        expiresAt,
      }),
      secret
    );
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("CALENDSO_ENCRYPTION_KEY", secret);
    vi.stubEnv("YANDEX_CLIENT_ID", "test-client");
    vi.stubEnv("YANDEX_CLIENT_SECRET", "test-client-secret");
    vi.mocked(prisma.credential.findUniqueOrThrow).mockResolvedValue({ key: stored(0) } as never);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            access_token: "test-new-access",
            refresh_token: "test-new-refresh",
            expires_in: 3600,
          })
        )
      )
    );
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });
  it("keeps a current access token without calling OAuth", async () => {
    vi.mocked(prisma.credential.findUniqueOrThrow).mockResolvedValue({
      key: stored(Date.now() / 1000 + 600),
    } as never);
    await refreshYandexCalendarCredential(credential);
    expect(fetch).not.toHaveBeenCalled();
    expect(prisma.credential.update).not.toHaveBeenCalled();
  });
  it("selects the matching Yandex identity without replacing a manual CalDAV connection", async () => {
    const encrypted = (data: object) => symmetricEncrypt(JSON.stringify(data), secret);
    const matching = {
      ...credential,
      id: 3,
      key: encrypted({ oauthProvider: "yandex", yandexUserId: "123" }),
    };
    vi.mocked(prisma.credential.findMany).mockResolvedValue([
      { ...credential, id: 1, key: encrypted({ username: "manual@example.test" }) },
      { ...credential, id: 2, key: encrypted({ oauthProvider: "yandex", yandexUserId: "999" }) },
      matching,
    ] as never);
    await expect(findYandexCalendarCredential(1, "123")).resolves.toEqual(matching);
    expect(prisma.credential.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { userId: 1, appId: "caldav-calendar" },
      })
    );
    expect(prisma.credential.update).not.toHaveBeenCalled();
  });
  it("fails closed when only another Yandex identity is connected", async () => {
    vi.mocked(prisma.credential.findMany).mockResolvedValue([{ ...credential, key: stored(0) }] as never);
    await expect(findYandexCalendarCredential(1, "123")).rejects.toThrow();
  });
  it("rotates and encrypts tokens while keeping secrets out of the URL", async () => {
    const result = await refreshYandexCalendarCredential(credential);
    expect(fetch).toHaveBeenCalledWith(
      "https://oauth.yandex.ru/token",
      expect.objectContaining({ method: "POST" })
    );
    expect(result.key).not.toContain("test-new-access");
    const key = JSON.parse(symmetricDecrypt(result.key as string, secret));
    expect(key.password).toBe("test-new-access");
    expect(key.refreshToken).toBe("test-new-refresh");
    expect(key.expiresAt).toBeGreaterThan(Date.now() / 1000 + 3500);
  });
  it("serializes concurrent refreshes within the single application process", async () => {
    await Promise.all([
      refreshYandexCalendarCredential(credential),
      refreshYandexCalendarCredential(credential),
    ]);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(prisma.credential.update).toHaveBeenCalledTimes(1);
  });
  it.each([400, 401, 429, 503])("does not overwrite credentials after OAuth HTTP %i", async (status) => {
    vi.mocked(fetch).mockResolvedValue(new Response("rejected", { status }));
    await expect(refreshYandexCalendarCredential(credential)).rejects.toThrow();
    expect(prisma.credential.update).not.toHaveBeenCalled();
  });
  it("does not persist a malformed token response", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ access_token: "" })));
    await expect(refreshYandexCalendarCredential(credential)).rejects.toThrow();
    expect(prisma.credential.update).not.toHaveBeenCalled();
  });
});
