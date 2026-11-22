import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, X } from "lucide-react";
import { useState } from "react";

import { type Column, DataTable } from "@/components/data-table";
import { FieldError } from "@/components/field-error";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { Member, RoleDefinition } from "@/gen/access/v1/access_pb";
import type { WhoAmIResponse } from "@/gen/app/v1/app_pb";
import { access, errorMessage, hasPrivilege, orgsWith } from "@/lib/api";
import { fieldErrors, invalidProps } from "@/lib/field-errors";
import { usePagedList } from "@/lib/paged-list";

// Roles the signed-in user may hand out in this org: those whose privileges they hold.
// Only a hint for the UI; the database refuses anything else.
function useGrantableRoles(me: WhoAmIResponse, orgId: bigint): RoleDefinition[] {
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => access.listRoles({}) });
  return (roles.data?.roles ?? []).filter((r) => r.privileges.every((p) => hasPrivilege(me, p, orgId)));
}

export function AccessPage({ me }: { me: WhoAmIResponse }) {
  const orgs = orgsWith(me, "access.manage");
  const [orgId, setOrgId] = useState(orgs[0]?.id);
  if (orgId === undefined) return null;

  return (
    <div className="space-y-6">
      {orgs.length > 1 && (
        <div className="flex items-center gap-3">
          <Label htmlFor="access-org">Organization</Label>
          <Select value={String(orgId)} onValueChange={(v) => setOrgId(BigInt(v))}>
            <SelectTrigger id="access-org" className="w-56">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {orgs.map((o) => (
                <SelectItem key={String(o.id)} value={String(o.id)}>
                  {o.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <MembersCard me={me} orgId={orgId} orgName={orgs.find((o) => o.id === orgId)?.name ?? ""} />
        </div>
        <GroupMappingsCard me={me} orgId={orgId} />
      </div>
    </div>
  );
}

function MembersCard({ me, orgId, orgName }: { me: WhoAmIResponse; orgId: bigint; orgName: string }) {
  const queryClient = useQueryClient();
  const grantable = useGrantableRoles(me, orgId).map((r) => r.code);
  const members = usePagedList(
    ["members", String(orgId)],
    (pageToken, query) => access.listMembers({ orgId, pageSize: 50, pageToken, query }),
    (page) => page.members,
  );
  const revoke = useMutation({
    mutationFn: (v: { userId: bigint; role: string }) => access.revokeRole({ orgId, ...v }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["members", String(orgId)] }),
  });

  const columns: Column<Member>[] = [
    {
      header: "User",
      cell: (m) => (
        <>
          <div className="font-medium">
            {m.displayName || m.subject}
            {m.userId === me.userId && <span className="text-muted-foreground"> (you)</span>}
          </div>
          {m.email && <div className="text-xs break-all text-muted-foreground">{m.email}</div>}
        </>
      ),
    },
    {
      header: "Roles",
      cell: (m) => (
        <div className="flex flex-wrap gap-1">
          {m.roles.map((r) =>
            r.source === "local" && m.userId !== me.userId && grantable.includes(r.role) ? (
              <Badge key={r.role} variant="secondary" className="gap-1 pr-1">
                {r.role}
                <button
                  type="button"
                  className="rounded-sm opacity-60 hover:opacity-100"
                  aria-label={`Revoke ${r.role} from ${m.displayName || m.subject}`}
                  onClick={() => revoke.mutate({ userId: m.userId, role: r.role })}
                >
                  <X className="size-3" />
                </button>
              </Badge>
            ) : (
              <Badge key={r.role} variant={r.source === "idp" ? "outline" : "secondary"}>
                {r.role}
                {r.source === "idp" && " · idp"}
              </Badge>
            ),
          )}
        </div>
      ),
    },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Members of {orgName}</CardTitle>
        <CardDescription>Roles from IdP groups are managed in the group mappings.</CardDescription>
        <CardAction>
          <GrantRoleDialog orgId={orgId} roles={grantable} />
        </CardAction>
      </CardHeader>
      <CardContent className="space-y-4">
        {revoke.isError && (
          <Alert variant="destructive">
            <AlertDescription>{errorMessage(revoke.error)}</AlertDescription>
          </Alert>
        )}
        <DataTable
          list={members}
          columns={columns}
          rowKey={(m) => String(m.userId)}
          label={`Members of ${orgName}`}
          filterLabel="Filter by name"
          empty={<p className="text-sm text-muted-foreground">No members yet.</p>}
        />
      </CardContent>
    </Card>
  );
}

function GrantRoleDialog({ orgId, roles }: { orgId: bigint; roles: string[] }) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("");
  const queryClient = useQueryClient();
  const grant = useMutation({
    mutationFn: () => access.grantRole({ orgId, email, role }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["members", String(orgId)] });
      setOpen(false);
      setEmail("");
    },
  });
  const errors = fieldErrors(grant.error);

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        grant.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus />
          Grant role
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            grant.mutate();
          }}
        >
          <DialogHeader>
            <DialogTitle>Grant role</DialogTitle>
            <DialogDescription>Only roles within your own privileges are listed.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="grant-email">Email</Label>
            <Input
              id="grant-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              {...invalidProps(errors.email, "grant-email")}
            />
            <FieldError message={errors.email} id="grant-email" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="grant-role">Role</Label>
            <Select value={role} onValueChange={setRole}>
              <SelectTrigger id="grant-role" className="w-full" {...invalidProps(errors.role, "grant-role")}>
                <SelectValue placeholder="Choose a role" />
              </SelectTrigger>
              <SelectContent>
                {roles.map((r) => (
                  <SelectItem key={r} value={r}>
                    {r}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldError message={errors.role} id="grant-role" />
          </div>
          {grant.isError && (
            <Alert variant="destructive">
              <AlertDescription>{errorMessage(grant.error)}</AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <DialogClose asChild>
              <Button type="button" variant="outline">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" disabled={!email.trim() || !role || grant.isPending}>
              Grant
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function GroupMappingsCard({ me, orgId }: { me: WhoAmIResponse; orgId: bigint }) {
  const queryClient = useQueryClient();
  const grantable = useGrantableRoles(me, orgId).map((r) => r.code);
  const [groupId, setGroupId] = useState("");
  const [role, setRole] = useState("");
  const key = ["mappings", String(orgId)];
  const mappings = useInfiniteQuery({
    queryKey: key,
    queryFn: ({ pageParam }) => access.listGroupMappings({ orgId, pageSize: 50, pageToken: pageParam }),
    initialPageParam: "",
    getNextPageParam: (last) => last.nextPageToken || undefined,
  });
  const rows = mappings.data?.pages.flatMap((p) => p.mappings);
  const refresh = () => queryClient.invalidateQueries({ queryKey: key });
  const add = useMutation({
    mutationFn: () => access.addGroupMapping({ orgId, groupId, role }),
    onSuccess: async () => {
      await refresh();
      setGroupId("");
    },
  });
  const remove = useMutation({
    mutationFn: (v: { groupId: string; role: string }) => access.removeGroupMapping({ orgId, ...v }),
    onSuccess: refresh,
  });
  const error = add.error ?? remove.error ?? mappings.error;
  const errors = fieldErrors(add.error);

  return (
    <Card className="h-fit">
      <CardHeader>
        <CardTitle>IdP group mappings</CardTitle>
        <CardDescription>Members of a group get the role at their next sign-in. Use the group ID.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{errorMessage(error)}</AlertDescription>
          </Alert>
        )}
        <ul className="space-y-2">
          {rows?.map((m) => (
            <li key={`${m.groupId}-${m.role}`} className="flex items-center justify-between gap-2 text-sm">
              <span className="min-w-0 truncate font-mono">{m.groupId}</span>
              <span className="flex shrink-0 items-center gap-1">
                <Badge variant="secondary">{m.role}</Badge>
                {grantable.includes(m.role) && (
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={`Remove mapping ${m.groupId} to ${m.role}`}
                    onClick={() => remove.mutate({ groupId: m.groupId, role: m.role })}
                  >
                    <X />
                  </Button>
                )}
              </span>
            </li>
          ))}
          {rows?.length === 0 && <li className="text-sm text-muted-foreground">No mappings yet.</li>}
        </ul>
        {mappings.hasNextPage && (
          <Button variant="outline" size="sm" onClick={() => void mappings.fetchNextPage()}>
            Load more
          </Button>
        )}
        <form
          className="space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            add.mutate();
          }}
        >
          <Label htmlFor="mapping-group">Add mapping</Label>
          <Input
            id="mapping-group"
            placeholder="Group ID"
            value={groupId}
            onChange={(e) => setGroupId(e.target.value)}
            {...invalidProps(errors.group_id, "mapping-group")}
          />
          <FieldError message={errors.group_id} id="mapping-group" />
          <div className="flex gap-2">
            <Select value={role} onValueChange={setRole}>
              <SelectTrigger aria-label="Mapping role" className="flex-1" {...invalidProps(errors.role, "mapping-role")}>
                <SelectValue placeholder="Role" />
              </SelectTrigger>
              <SelectContent>
                {grantable.map((r) => (
                  <SelectItem key={r} value={r}>
                    {r}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button type="submit" disabled={!groupId.trim() || !role || add.isPending}>
              Add
            </Button>
          </div>
          <FieldError message={errors.role} id="mapping-role" />
        </form>
      </CardContent>
    </Card>
  );
}
