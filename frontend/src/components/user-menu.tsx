import { LogOut } from "lucide-react";
import { useRef } from "react";

import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { WhoAmIResponse } from "@/gen/app/v1/app_pb";

export function displayName(me: WhoAmIResponse) {
  return me.displayName || me.subject;
}

export function UserMenu({ me }: { me: WhoAmIResponse }) {
  const logout = useRef<HTMLFormElement>(null);
  const name = displayName(me);
  const initials = name
    .split(/\s+/)
    .map((p) => p[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <>
      {/* A plain same-origin form POST: covered by CrossOriginProtection, no fetch needed. */}
      <form ref={logout} method="post" action="/auth/logout" hidden />
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" className="h-9 gap-2 px-2">
            {/* The name, not the initials, is the button's accessible name, also on mobile. */}
            <Avatar className="size-7" aria-hidden>
              <AvatarFallback className="text-xs text-foreground">{initials}</AvatarFallback>
            </Avatar>
            <span className="sr-only text-sm sm:not-sr-only">{name}</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel className="flex flex-col">
            <span>{name}</span>
            {me.email && <span className="text-xs font-normal text-muted-foreground">{me.email}</span>}
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => logout.current?.requestSubmit()}>
            <LogOut />
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}
