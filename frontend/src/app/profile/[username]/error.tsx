'use client';
import { AppShell } from "@/components/app-shell";

export default function ProfileError({ reset }: { reset: () => void }) {
  return (
    <AppShell>
      <div className="text-center p-8">
        <p className="text-red-500">Failed to load profile.</p>
        <button onClick={reset} className="mt-4">Try again</button>
      </div>
    </AppShell>
  );
}
