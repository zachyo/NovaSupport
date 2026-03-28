import { AppShell } from "@/components/app-shell";

export default function ProfileLoading() {
  return (
    <AppShell>
      <div className="animate-pulse space-y-4 p-8 max-w-2xl mx-auto">
        <div className="h-16 w-16 rounded-full bg-steel-200" />
        <div className="h-6 w-48 rounded bg-steel-200" />
        <div className="h-4 w-32 rounded bg-steel-200" />
        <div className="h-20 w-full rounded bg-steel-200" />
      </div>
    </AppShell>
  );
}
