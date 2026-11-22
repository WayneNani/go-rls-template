import { Code, ConnectError } from "@connectrpc/connect";

import { ViolationsSchema } from "@/gen/buf/validate/validate_pb";

// Field path ("name", "address.city") -> message, from the violations the server attaches
// to InvalidArgument when a request breaks its rules in proto (protovalidate). Empty for
// any other error; errorMessage in api.ts stays the general message.
export function fieldErrors(err: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!err) return out;
  const e = ConnectError.from(err);
  if (e.code !== Code.InvalidArgument) return out;
  for (const v of e.findDetails(ViolationsSchema).flatMap((d) => d.violations)) {
    const path = (v.field?.elements ?? []).map((el) => el.fieldName).join(".");
    out[path] ??= v.message.charAt(0).toUpperCase() + v.message.slice(1) + ".";
  }
  return out;
}

// Spread on the control: marks it invalid and points to the message <FieldError> renders.
export function invalidProps(message: string | undefined, id: string) {
  return message ? { "aria-invalid": true, "aria-describedby": `${id}-error` } : {};
}
