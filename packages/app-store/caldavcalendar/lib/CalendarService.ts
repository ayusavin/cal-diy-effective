import BaseCalendarService from "@calcom/lib/CalendarService";
import { symmetricDecrypt } from "@calcom/lib/crypto";
import type { Calendar } from "@calcom/types/Calendar";
import type { CredentialPayload } from "@calcom/types/Credential";
import { refreshYandexCalendarCredential } from "./yandexOAuth";

class CalDavCalendarService extends BaseCalendarService {
  constructor(credential: CredentialPayload) {
    super(credential, "caldav_calendar");
  }
}

/**
 * Factory function that creates a CalDAV Calendar service instance.
 * This is exported instead of the class to prevent internal types
 * from leaking into the emitted .d.ts file.
 */
export default function BuildCalendarService(credential: CredentialPayload): Calendar {
  const service = new CalDavCalendarService(credential);
  const key = JSON.parse(
    symmetricDecrypt(credential.key as string, process.env.CALENDSO_ENCRYPTION_KEY || "")
  );
  if (key.oauthProvider !== "yandex") return service;
  // Refresh once per public operation; internal CalDAV calls share the same token.
  return new Proxy(service, {
    get(target, property) {
      const value = Reflect.get(target, property);
      if (typeof value !== "function") return value;
      return async (...args: unknown[]) => {
        const current = await refreshYandexCalendarCredential(credential);
        const freshService = new CalDavCalendarService(current);
        return Reflect.get(freshService, property).apply(freshService, args);
      };
    },
  });
}
