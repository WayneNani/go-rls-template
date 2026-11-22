import { Building2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { WhoAmIResponse } from "@/gen/app/v1/app_pb";

export function AccessCard({ me }: { me: WhoAmIResponse }) {
  return (
    <Card className="h-fit">
      <CardHeader>
        <CardTitle>Your access</CardTitle>
        <CardDescription>Roles per organization. IdP roles come from your groups at sign-in.</CardDescription>
      </CardHeader>
      <CardContent>
        {me.roles.length === 0 ? (
          <p className="text-sm text-muted-foreground">No roles yet. Ask an administrator for access.</p>
        ) : (
          <ul className="space-y-3">
            {me.roles.map((r) => (
              <li key={`${r.orgId}-${r.role}`} className="flex items-center justify-between gap-2">
                <span className="flex min-w-0 items-center gap-2 text-sm">
                  <Building2 className="size-4 shrink-0 text-muted-foreground" />
                  <span className="truncate">{r.orgName}</span>
                </span>
                <span className="flex shrink-0 gap-1">
                  <Badge variant="secondary">{r.role}</Badge>
                  <Badge variant="outline">{r.source}</Badge>
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
