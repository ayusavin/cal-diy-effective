import BuildCalendarService from "@calcom/app-store/caldavcalendar/lib/CalendarService";
import {
  findYandexCalendarCredential,
  isYandexCredential,
  refreshYandexCalendarCredential,
} from "@calcom/app-store/caldavcalendar/lib/yandexOAuth";
import { symmetricDecrypt, symmetricEncrypt } from "@calcom/lib/crypto";
import { ErrorWithCode } from "@calcom/lib/errors";
import prisma from "@calcom/prisma";
import { credentialForCalendarServiceSelect } from "@calcom/prisma/selects/credential";
import type { Account } from "next-auth";
import YandexProvider from "next-auth/providers/yandex";
import { z } from "zod";

export const isYandexLoginEnabled = () => process.env.YANDEX_LOGIN_ENABLED === "true";
const profileSchema = z.object({
  id: z.string().regex(/^\d+$/),
  default_email: z.string().email(),
  first_name: z.string().optional(),
  last_name: z.string().optional(),
  real_name: z.string().optional(),
  display_name: z.string().optional(),
  is_avatar_empty: z.boolean().default(true),
  default_avatar_id: z.string().optional(),
});

export function corporateUsername(email: string, domain: string) {
  const [username, emailDomain, extra] = email.toLowerCase().split("@");
  if (extra || emailDomain !== domain.toLowerCase() || !/^[a-z0-9][a-z0-9._-]*$/.test(username)) {
    throw ErrorWithCode.Factory.Unauthorized("Corporate Yandex account required");
  }
  return username;
}

export function parseCorporateYandexProfile(data: unknown) {
  const profile = profileSchema.parse(data);
  corporateUsername(profile.default_email, process.env.YANDEX_ALLOWED_EMAIL_DOMAIN || "");
  return profile;
}

export async function revalidateYandexSession(id: string) {
  const account = await prisma.account.findUniqueOrThrow({
    where: { provider_providerAccountId: { provider: "yandex", providerAccountId: id } },
    select: { userId: true },
  });
  const credential = await findYandexCalendarCredential(account.userId, id);
  const current = await refreshYandexCalendarCredential(credential);
  const key = JSON.parse(symmetricDecrypt(current.key as string, process.env.CALENDSO_ENCRYPTION_KEY || ""));
  const response = await fetch("https://login.yandex.ru/info?format=json", {
    headers: { Authorization: `OAuth ${key.password}` },
    signal: AbortSignal.timeout(10000),
    cache: "no-store",
  });
  if (!response.ok) throw ErrorWithCode.Factory.Unauthorized("Yandex sign-in required");
  const profile = parseCorporateYandexProfile(await response.json());
  if (profile.id !== id) {
    throw ErrorWithCode.Factory.Unauthorized("Yandex identity mismatch");
  }
  return profile;
}

export function yandexProvider() {
  return YandexProvider({
    clientId: process.env.YANDEX_CLIENT_ID || "",
    clientSecret: process.env.YANDEX_CLIENT_SECRET || "",
    checks: ["pkce", "state"],
    authorization: {
      params: {
        scope: "login:info login:email login:avatar calendar:all telemost-api:conferences.create",
      },
    },
  });
}

export async function signInWithYandex(account: Account, rawProfile: unknown) {
  const profile = parseCorporateYandexProfile(rawProfile);
  if (profile.id !== account.providerAccountId || !account.access_token || !account.refresh_token) {
    throw ErrorWithCode.Factory.Unauthorized("Yandex authorization is incomplete");
  }
  const email = profile.default_email.toLowerCase();
  const username = corporateUsername(email, process.env.YANDEX_ALLOWED_EMAIL_DOMAIN || "");
  const name =
    [profile.first_name, profile.last_name].filter(Boolean).join(" ").trim() ||
    profile.real_name ||
    profile.display_name;
  if (!name) throw ErrorWithCode.Factory.Unauthorized("Corporate profile name is missing");
  const avatarUrl =
    !profile.is_avatar_empty && profile.default_avatar_id
      ? `https://avatars.yandex.net/get-yapic/${encodeURIComponent(profile.default_avatar_id)}/islands-200`
      : null;
  const identity = await prisma.account.findUnique({
    where: { provider_providerAccountId: { provider: "yandex", providerAccountId: profile.id } },
    select: { userId: true },
  });
  const key = symmetricEncrypt(
    JSON.stringify({
      username: email,
      password: account.access_token,
      url: "https://caldav.yandex.ru",
      oauthProvider: "yandex",
      yandexUserId: profile.id,
      refreshToken: account.refresh_token,
      expiresAt: account.expires_at,
    }),
    process.env.CALENDSO_ENCRYPTION_KEY || ""
  );
  const user = await prisma.$transaction(async (tx) => {
    // A matching email alone must never silently attach a different identity.
    const conflictingUser = await tx.user.findFirst({
      where: { OR: [{ email }, { username }] },
      select: { id: true },
    });
    if (conflictingUser && conflictingUser.id !== identity?.userId) {
      throw ErrorWithCode.Factory.Unauthorized("Corporate account already belongs to another identity");
    }
    const data = { email, name, avatarUrl, emailVerified: new Date() };
    const user = identity
      ? await tx.user.update({ where: { id: identity.userId }, data, select: { id: true, email: true } })
      : await tx.user.create({
          data: {
            ...data,
            username,
            locale: "ru",
            timeZone: "Asia/Omsk",
            role: email === process.env.YANDEX_OWNER_EMAIL?.toLowerCase() ? "ADMIN" : "USER",
            identityProvider: "CAL",
            creationSource: "WEBAPP",
            accounts: { create: { provider: "yandex", providerAccountId: profile.id, type: "oauth" } },
          },
          select: { id: true, email: true },
        });
    await tx.app.upsert({
      where: { slug: "caldav-calendar" },
      create: { slug: "caldav-calendar", dirName: "caldavcalendar", categories: ["calendar"], enabled: true },
      update: { enabled: true },
    });
    const credentials = await tx.credential.findMany({
      where: { userId: user.id, appId: "caldav-calendar" },
      select: credentialForCalendarServiceSelect,
    });
    const credential = credentials.find((candidate) => isYandexCredential(candidate, profile.id));
    if (credential) {
      await tx.credential.update({ where: { id: credential.id }, data: { key, invalid: false } });
    } else {
      await tx.credential.create({
        data: { userId: user.id, appId: "caldav-calendar", type: "caldav_calendar", key },
      });
    }
    return user;
  });
  const credential = await findYandexCalendarCredential(user.id, profile.id);
  const calendarService = BuildCalendarService(credential);
  const calendars = await calendarService.listCalendars();
  if (!calendars.length) throw ErrorWithCode.Factory.Unauthorized("Yandex calendar is not accessible");
  const main = calendars.find((calendar) => calendar.primary) || calendars[0];
  await prisma.$transaction(async (tx) => {
    const selected = await tx.selectedCalendar.findFirst({
      where: { userId: user.id, integration: "caldav_calendar", externalId: main.externalId },
      select: { id: true },
    });
    if (!selected) {
      await tx.selectedCalendar.create({
        data: {
          userId: user.id,
          integration: "caldav_calendar",
          externalId: main.externalId,
          credentialId: credential.id,
        },
      });
    }
    const destination = {
      integration: "caldav_calendar",
      externalId: main.externalId,
      credentialId: credential.id,
      primaryEmail: email,
    };
    await tx.destinationCalendar.upsert({
      where: { userId: user.id },
      create: { userId: user.id, ...destination },
      update: {},
    });
  });
  return true;
}
