import { timestampDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { FolderKanban, Pencil } from "lucide-react";
import { useState } from "react";

import { type Column, DataTable } from "@/components/data-table";
import { FieldError } from "@/components/field-error";
import { NewProjectDialog } from "@/components/new-project-dialog";
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
import type { Project, WhoAmIResponse } from "@/gen/app/v1/app_pb";
import { api, errorMessage, hasPrivilege } from "@/lib/api";
import { fieldErrors, invalidProps } from "@/lib/field-errors";
import { usePagedList } from "@/lib/paged-list";

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

const columns: Column<Project>[] = [
  { header: "Name", cell: (p) => <span className="font-medium">{p.name}</span> },
  { header: "Organization", cell: (p) => <Badge variant="secondary">{p.orgName}</Badge> },
  {
    header: "Created",
    cell: (p) => (p.createdAt ? dateFormat.format(timestampDate(p.createdAt)) : ""),
    className: "hidden text-right text-muted-foreground sm:table-cell",
  },
];

export function ProjectsCard({ me }: { me: WhoAmIResponse }) {
  const canRead = me.privileges.some((p) => p.privilege === "project.read");
  const projects = usePagedList(
    ["projects"],
    (pageToken, query) => api.listProjects({ pageSize: 20, pageToken, query }),
    (page) => page.projects,
    { enabled: canRead },
  );

  // Only a hint for the UI. The server decides (interceptor + RLS).
  const writableOrgs = me.roles
    .filter((r) => me.privileges.some((p) => p.orgId === r.orgId && p.privilege === "project.write"))
    .filter((r, i, all) => all.findIndex((x) => x.orgId === r.orgId) === i);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Projects</CardTitle>
        <CardDescription>Everything you can see is filtered by the database.</CardDescription>
        {writableOrgs.length > 0 && (
          <CardAction>
            <NewProjectDialog orgs={writableOrgs} />
          </CardAction>
        )}
      </CardHeader>
      <CardContent>
        {!canRead ? (
          <Empty text="You can't see projects in any organization yet." />
        ) : (
          <DataTable
            list={projects}
            columns={columns}
            rowKey={(p) => String(p.id)}
            label="Projects"
            filterLabel="Filter projects"
            empty={<Empty text="No projects yet." />}
            actions={(p) => hasPrivilege(me, "project.write", p.orgId) && <RenameProjectDialog project={p} />}
          />
        )}
      </CardContent>
    </Card>
  );
}

// Sends the version it read: if someone renamed the project in between, the server answers
// Aborted instead of overwriting their change, and the list is reloaded.
function RenameProjectDialog({ project }: { project: Project }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(project.name);
  const queryClient = useQueryClient();

  const rename = useMutation({
    mutationFn: () => api.updateProject({ id: project.id, version: project.version, name }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      setOpen(false);
    },
    onError: async (err) => {
      if (ConnectError.from(err).code === Code.Aborted) {
        await queryClient.invalidateQueries({ queryKey: ["projects"] });
      }
    },
  });

  const errors = fieldErrors(rename.error);

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        setName(project.name);
        rename.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label={`Rename ${project.name}`}>
          <Pencil />
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            rename.mutate();
          }}
        >
          <DialogHeader>
            <DialogTitle>Rename project</DialogTitle>
            <DialogDescription>{project.orgName}</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="rename">Name</Label>
            <Input
              id="rename"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              {...invalidProps(errors.name, "rename")}
            />
            <FieldError message={errors.name} id="rename" />
          </div>
          {rename.isError && (
            <Alert variant="destructive">
              <AlertDescription>{errorMessage(rename.error)}</AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <DialogClose asChild>
              <Button type="button" variant="outline">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" disabled={!name.trim() || name === project.name || rename.isPending}>
              Rename
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div className="flex flex-col items-center gap-2 py-10 text-center text-sm text-muted-foreground">
      <FolderKanban className="size-8" />
      {text}
    </div>
  );
}
