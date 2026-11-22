import { Code, ConnectError, createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";

import { AccessService } from "@/gen/access/v1/access_pb";
import { AppService } from "@/gen/app/v1/app_pb";
import type { WhoAmIResponse } from "@/gen/app/v1/app_pb";
// scaffold: service imports above this line

// The only way to the backend (ESLint forbids fetch). Same origin: the session cookie
// rides along, and Connect's JSON content type makes cross-site form posts impossible.
const transport = createConnectTransport({ baseUrl: "/api" });
export const api = createClient(AppService, transport);
export const access = createClient(AccessService, transport);
// scaffold: clients above this line

export function isUnauthenticated(err: unknown): boolean {
  return ConnectError.from(err).code === Code.Unauthenticated;
}

// Step-up: the method declares (authz.v1.max_auth_age) and the sign-in is older
// (authz.ReauthRequired in internal/authz). <ReauthDialog> offers a re-authentication.
export function isReauthRequired(err: unknown): boolean {
  const e = ConnectError.from(err);
  return e.code === Code.FailedPrecondition && e.rawMessage === "recent sign-in required";
}

export function errorMessage(err: unknown): string {
  const e = ConnectError.from(err);
  if (isReauthRequired(e)) return "Please confirm it's you, then try again.";
  switch (e.code) {
    case Code.PermissionDenied:
      return "You don't have permission to do that.";
    case Code.InvalidArgument:
      return "Please check your input.";
    case Code.NotFound:
      return "Not found. A user appears here after their first sign-in with a verified email.";
    case Code.AlreadyExists:
      return "Already granted, here or through an IdP group.";
    case Code.Aborted:
      return "Someone else changed this in the meantime. The list is reloaded; please try again.";
    default: {
      // X-Request-Id (internal/telemetry): support finds the request in the log by it.
      const id = e.metadata.get("x-request-id");
      return `Something went wrong. Please try again.${id ? ` Reference: ${id}` : ""}`;
    }
  }
}

// UI hints only: the server decides (interceptor and RLS).
export function hasPrivilege(me: WhoAmIResponse, privilege: string, orgId?: bigint): boolean {
  return me.privileges.some((p) => p.privilege === privilege && (orgId === undefined || p.orgId === orgId));
}

export function orgsWith(me: WhoAmIResponse, privilege: string): { id: bigint; name: string }[] {
  const seen = new Map<bigint, string>();
  for (const r of me.roles) {
    if (hasPrivilege(me, privilege, r.orgId)) seen.set(r.orgId, r.orgName);
  }
  return [...seen].map(([id, name]) => ({ id, name }));
}
