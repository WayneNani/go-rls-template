import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { useState } from "react";

import { FieldError } from "@/components/field-error";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
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
import type { Role } from "@/gen/app/v1/app_pb";
import { api, errorMessage } from "@/lib/api";
import { fieldErrors, invalidProps } from "@/lib/field-errors";

export function NewProjectDialog({ orgs }: { orgs: Role[] }) {
  const [open, setOpen] = useState(false);
  const [orgId, setOrgId] = useState(orgs.length === 1 && orgs[0] ? String(orgs[0].orgId) : "");
  const [name, setName] = useState("");
  const queryClient = useQueryClient();

  const create = useMutation({
    mutationFn: () => api.createProject({ orgId: BigInt(orgId), name }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["projects"] });
      setOpen(false);
      setName("");
    },
  });

  const errors = fieldErrors(create.error);

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        create.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus />
          New project
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <DialogHeader>
            <DialogTitle>New project</DialogTitle>
            <DialogDescription>Only organizations where you may create projects are listed.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="org">Organization</Label>
            <Select value={orgId} onValueChange={setOrgId}>
              <SelectTrigger id="org" className="w-full" {...invalidProps(errors.org_id, "org")}>
                <SelectValue placeholder="Choose an organization" />
              </SelectTrigger>
              <SelectContent>
                {orgs.map((o) => (
                  <SelectItem key={String(o.orgId)} value={String(o.orgId)}>
                    {o.orgName}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldError message={errors.org_id} id="org" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="name">Name</Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              {...invalidProps(errors.name, "name")}
            />
            <FieldError message={errors.name} id="name" />
          </div>
          {create.isError && (
            <Alert variant="destructive">
              <AlertDescription>{errorMessage(create.error)}</AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <DialogClose asChild>
              <Button type="button" variant="outline">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" disabled={!orgId || !name.trim() || create.isPending}>
              Create
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
