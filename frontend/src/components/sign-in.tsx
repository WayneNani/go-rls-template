import { LogIn, ShieldCheck } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function SignIn({ failed = false }: { failed?: boolean }) {
  return (
    <main className="flex min-h-svh items-center justify-center bg-muted/40 p-4">
      <Card className="w-full max-w-sm">
        <CardHeader className="text-center">
          <ShieldCheck className="mx-auto mb-2 size-10 text-primary" />
          <CardTitle className="text-xl">
            <h1>Welcome</h1>
          </CardTitle>
          <CardDescription>Sign in with your organization's account.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {failed && (
            <Alert variant="destructive">
              <AlertDescription>The server could not be reached. Please try again.</AlertDescription>
            </Alert>
          )}
          <Button asChild className="w-full" size="lg">
            <a href="/auth/login">
              <LogIn />
              Sign in
            </a>
          </Button>
        </CardContent>
      </Card>
    </main>
  );
}
