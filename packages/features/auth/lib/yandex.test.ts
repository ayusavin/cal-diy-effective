import { symmetricEncrypt } from "@calcom/lib/crypto";
import { findYandexCalendarCredential } from "@calcom/app-store/caldavcalendar/lib/yandexOAuth";
import prisma from "@calcom/prisma";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@calcom/app-store/caldavcalendar/lib/CalendarService", () => ({ default: vi.fn() }));
vi.mock("@calcom/app-store/caldavcalendar/lib/yandexOAuth", () => ({
  findYandexCalendarCredential: vi.fn(),
  isYandexCredential: vi.fn(),
  refreshYandexCalendarCredential: vi.fn(async (credential) => credential),
}));
vi.mock("@calcom/prisma", () => ({
  default: { account: { findUniqueOrThrow: vi.fn() } },
}));
import {
  corporateUsername,
  parseCorporateYandexProfile,
  revalidateYandexSession,
  signInWithYandex,
  yandexProvider,
} from "./yandex";

const profile = {
  id: "123",
  default_email: "ivan.petrov@effective.band",
  first_name: "Ivan",
  last_name: "Petrov",
  is_avatar_empty: false,
  default_avatar_id: "456",
};

describe("corporate Yandex domain admission without Directory API", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("YANDEX_ALLOWED_EMAIL_DOMAIN", "effective.band");
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });
  it("uses the exact mailbox local part", () => {
    expect(corporateUsername("Ivan.Petrov@effective.band", "effective.band")).toBe("ivan.petrov");
  });
  it.each([
    "ivan@yandex.ru",
    "ivan@effective.band.attacker.test",
    "ivan@foo.effective.band",
    "ivan@effective.band@attacker.test",
    "@effective.band",
  ])("rejects an outside address: %s", (email) => {
    expect(() => corporateUsername(email, "effective.band")).toThrow();
  });
  it("accepts the provider's corporate profile without Directory API access", () => {
    expect(parseCorporateYandexProfile(profile)).toMatchObject(profile);
    expect(fetch).not.toHaveBeenCalled();
  });
  it("normalizes email case for domain comparison", () => {
    expect(
      parseCorporateYandexProfile({ ...profile, default_email: "Ivan.Petrov@Effective.Band" })
    ).toBeDefined();
  });
  it.each([
    {},
    { id: "123" },
    { ...profile, id: "../123" },
    { ...profile, default_email: "ivan@yandex.ru" },
  ])("denies a malformed or foreign provider profile %j", (data) => {
    expect(() => parseCorporateYandexProfile(data)).toThrow();
  });
  it("rejects a foreign account before touching storage or the calendar", async () => {
    await expect(
      signInWithYandex(
        {
          provider: "yandex",
          providerAccountId: "123",
          type: "oauth",
          access_token: "test",
          refresh_token: "test",
        },
        { ...profile, default_email: "ivan@yandex.ru" }
      )
    ).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
  it("rejects mismatched OAuth and profile IDs", async () => {
    await expect(
      signInWithYandex(
        {
          provider: "yandex",
          providerAccountId: "999",
          type: "oauth",
          access_token: "test",
          refresh_token: "test",
        },
        profile
      )
    ).rejects.toThrow();
  });
  it("enables state and PKCE without automatic email account linking", () => {
    expect(yandexProvider().options).toMatchObject({ checks: ["pkce", "state"] });
    expect(yandexProvider().allowDangerousEmailAccountLinking).not.toBe(true);
  });
});

describe("Yandex session revalidation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv("YANDEX_ALLOWED_EMAIL_DOMAIN", "effective.band");
    vi.stubEnv("CALENDSO_ENCRYPTION_KEY", "00000000000000000000000000000000");
    vi.mocked(prisma.account.findUniqueOrThrow).mockResolvedValue({ userId: 1 } as never);
    vi.mocked(findYandexCalendarCredential).mockResolvedValue({
      key: symmetricEncrypt(
        JSON.stringify({ password: "test-only-access" }),
        "00000000000000000000000000000000"
      ),
    } as never);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify(profile))));
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });
  it("revalidates identity using only the user's own Yandex ID token", async () => {
    await expect(revalidateYandexSession("123")).resolves.toMatchObject(profile);
    expect(findYandexCalendarCredential).toHaveBeenCalledWith(1, "123");
    expect(fetch).toHaveBeenCalledWith(
      "https://login.yandex.ru/info?format=json",
      expect.objectContaining({ cache: "no-store" })
    );
  });
  it.each([401, 403, 429, 503])("fails closed on userinfo HTTP %i", async (status) => {
    vi.mocked(fetch).mockResolvedValue(new Response("rejected", { status }));
    await expect(revalidateYandexSession("123")).rejects.toThrow();
  });
  it.each([
    { id: "999" },
    { default_email: "ivan@yandex.ru" },
  ])("rejects a changed identity or domain %j", async (change) => {
    vi.mocked(fetch).mockResolvedValue(new Response(JSON.stringify({ ...profile, ...change })));
    await expect(revalidateYandexSession("123")).rejects.toThrow();
  });
});
