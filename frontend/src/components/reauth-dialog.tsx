import { useQueryClient } from "@tanstack/react-query";
import { LogIn } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { isReauthRequired } from "@/lib/api";

// Opens when any mutation fails because the method needs a recent sign-in
// (option (authz.v1.max_auth_age)). The re-authentication returns to the current page;
// the user then repeats the action (nothing is replayed automatically).
export function ReauthDialog() {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  useEffect(
    () =>
      queryClient.getMutationCache().subscribe((e) => {
        if (e.type === "updated" && e.action.type === "error" && isReauthRequired(e.action.error)) setOpen(true);
      }),
    [queryClient],
  );
  const back = location.pathname + location.hash;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Confirm it's you</DialogTitle>
          <DialogDescription>
            Changing access needs a recent sign-in. Sign in again, then repeat the change.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button asChild>
            <a href={`/auth/login?reauth=1&return=${encodeURIComponent(back)}`}>
              <LogIn />
              Sign in again
            </a>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
