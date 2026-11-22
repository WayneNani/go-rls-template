// The server's message for one field, under the control (see invalidProps in lib/field-errors).
export function FieldError({ message, id }: { message: string | undefined; id: string }) {
  if (!message) return null;
  return (
    <p id={`${id}-error`} className="text-sm text-destructive">
      {message}
    </p>
  );
}
