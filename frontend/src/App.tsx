import { useQuery } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";

import { AccessCard } from "@/components/access-card";
import { AccessPage } from "@/components/access-page";
import { ProjectsCard } from "@/components/projects-card";
import { ReauthDialog } from "@/components/reauth-dialog";
import { SignIn } from "@/components/sign-in";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { UserMenu } from "@/components/user-menu";
// scaffold: page imports above this line
import type { WhoAmIResponse } from "@/gen/app/v1/app_pb";
import { api, hasPrivilege, isUnauthenticated } from "@/lib/api";

// A page in the navigation. It shows when the user holds `privilege` in some org (a hint;
// the server decides). The hash keeps the page across reloads; there is no router.
interface PageDef {
  hash: string;
  title: string;
  privilege?: string;
  render: (me: WhoAmIResponse) => ReactNode;
}

const home: PageDef = {
  hash: "",
  title: "Projects",
  render: (me) => (
    <div className="grid gap-6 lg:grid-cols-3">
      <div className="lg:col-span-2">
        <ProjectsCard me={me} />
      </div>
      <AccessCard me={me} />
    </div>
  ),
};

const pages: PageDef[] = [
  home,
  // scaffold: pages above this line
  { hash: "access", title: "Access", privilege: "access.manage", render: (me) => <AccessPage me={me} /> },
];

function useHash(): string {
  const [hash, setHash] = useState(() => location.hash.slice(1));
  useEffect(() => {
    const onChange = () => setHash(location.hash.slice(1));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return hash;
}

export function App() {
  const me = useQuery({ queryKey: ["whoAmI"], queryFn: () => api.whoAmI({}) });
  const hash = useHash();

  if (me.isPending) {
    return (
      <div className="mx-auto max-w-6xl space-y-4 p-4 sm:p-8">
        <Skeleton className="h-10 w-48" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }
  if (me.isError) {
    return isUnauthenticated(me.error) ? <SignIn /> : <SignIn failed />;
  }

  const visible = pages.filter((p) => !p.privilege || hasPrivilege(me.data, p.privilege));
  const current = visible.find((p) => p.hash === hash) ?? home;

  return (
    <div className="min-h-svh bg-muted/40">
      <header className="sticky top-0 z-10 border-b bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-2 px-4 sm:px-8">
          <div className="flex min-w-0 items-center gap-4">
            <div className="flex items-center gap-2 font-semibold">
              <ShieldCheck className="size-5 text-primary" />
              {/* Phones: the icon only, so the navigation fits. */}
              <span className="hidden sm:inline">
                Starter
              </span>
            </div>
            {visible.length > 1 && (
              <nav className="flex gap-1 overflow-x-auto">
                {visible.map((p) => (
                  <Button
                    key={p.hash}
                    variant={p === current ? "secondary" : "ghost"}
                    size="sm"
                    onClick={() => (location.hash = p.hash)}
                  >
                    {p.title}
                  </Button>
                ))}
              </nav>
            )}
          </div>
          <UserMenu me={me.data} />
        </div>
      </header>
      <main className="mx-auto max-w-6xl p-4 sm:p-8">
        <h1 className="sr-only">{current.title}</h1>
        {current.render(me.data)}
      </main>
      <ReauthDialog />
    </div>
  );
}
