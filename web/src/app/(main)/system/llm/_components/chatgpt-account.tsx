"use client";

import * as React from "react";

import { ExternalLinkIcon, Loader2Icon, LogOutIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { t } from "@/i18n";
import { api } from "@/lib/api";
import type { ChatGPTAccount } from "@/lib/types";

function statusBadge(a: ChatGPTAccount) {
  if (a.status === "active")
    return (
      <Badge variant="outline" className="border-emerald-500/50 text-emerald-600 dark:text-emerald-400">
        {t("Signed in")}
      </Badge>
    );
  if (a.status === "plan_disabled")
    return (
      <Badge variant="outline" className="border-amber-500/50 text-amber-600 dark:text-amber-400">
        {t("Plan usage not allowed")}
      </Badge>
    );
  return (
    <Badge variant="outline" className="border-muted-foreground/40 text-muted-foreground">
      {t("Signed out")}
    </Badge>
  );
}

// ChatGPTAccountPicker replaces the base URL / API key fields for a chatgpt-plan profile: it signs in with
// ChatGPT (a browser tab to auth.openai.com that redirects back to ARTEX), picks the account the profile uses,
// and loads the models that account can use.
export function ChatGPTAccountPicker({
  accountId,
  onAccountChange,
  onPickModel,
}: {
  accountId: string;
  onAccountChange: (id: string) => void;
  onPickModel: (model: string) => void;
}) {
  const [accounts, setAccounts] = React.useState<ChatGPTAccount[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [paste, setPaste] = React.useState("");
  const [waiting, setWaiting] = React.useState(false); // a sign-in tab is open
  const [models, setModels] = React.useState<{ id: string; name: string }[]>([]);
  const [loadingModels, setLoadingModels] = React.useState(false);

  const reload = React.useCallback(async () => {
    try {
      const r = await api.chatgptAccounts();
      setAccounts(r.accounts);
      return r.accounts;
    } catch (e) {
      toast.error(t("Could not load ChatGPT accounts: {error}", { error: (e as Error).message }));
      return [];
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void reload();
  }, [reload]);

  // While a sign-in tab is open, poll so the account appears without a manual refresh.
  React.useEffect(() => {
    if (!waiting) return;
    const before = new Set(accounts.map((a) => `${a.id}:${a.updated_at}`));
    const timer = window.setInterval(async () => {
      const list = await reload();
      const changed = list.find((a) => !before.has(`${a.id}:${a.updated_at}`));
      if (changed) {
        setWaiting(false);
        onAccountChange(changed.id);
        toast.success(t("Signed in as {email}", { email: changed.email }));
      }
    }, 2000);
    const stop = window.setTimeout(() => setWaiting(false), 10 * 60 * 1000);
    return () => {
      window.clearInterval(timer);
      window.clearTimeout(stop);
    };
  }, [waiting, accounts, reload, onAccountChange]);

  const selected = accounts.find((a) => a.id === accountId);

  async function signIn(reauth?: ChatGPTAccount, enablePlan = false) {
    if (busy) return;
    setBusy(true);
    try {
      const r = await api.chatgptSignin(reauth?.id, enablePlan);
      // No "noopener" feature: with it window.open always returns null, hiding a real pop-up block.
      const tab = window.open(r.authorize_url, "_blank");
      if (tab) tab.opener = null;
      else {
        // Pop-up blocked: navigate in a new tab via a link the user clicks.
        toast.message(t("Open the sign-in page"), {
          action: { label: t("Open"), onClick: () => window.open(r.authorize_url, "_blank", "noopener,noreferrer") },
        });
      }
      setWaiting(true);
    } catch (e) {
      toast.error(t("Could not start the ChatGPT sign-in: {error}", { error: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  async function submitPaste() {
    if (!paste.trim() || busy) return;
    setBusy(true);
    try {
      const r = await api.chatgptPasteCallback(paste.trim());
      setPaste("");
      setWaiting(false);
      await reload();
      onAccountChange(r.account.id);
      toast.success(t("Signed in as {email}", { email: r.account.email }));
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function signOut(a: ChatGPTAccount) {
    if (busy) return;
    setBusy(true);
    try {
      const r = await api.chatgptSignout(a.id);
      await reload();
      if (r.revoked) toast.success(t("Signed out of {email}", { email: a.email }));
      else
        toast.warning(
          t(
            "Signed out locally; OpenAI did not confirm the revocation. You can also disconnect ARTEX in ChatGPT Settings.",
          ),
        );
    } catch (e) {
      toast.error(t("Sign-out failed: {error}", { error: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  async function loadModels() {
    if (!accountId || loadingModels) return;
    setLoadingModels(true);
    try {
      const r = await api.chatgptModels(accountId);
      if (r.ok && r.models && r.models.length > 0) setModels(r.models);
      else toast.error(t("Failed to load models: {error}", { error: r.error ?? t("no models returned") }));
    } catch (e) {
      toast.error(t("Failed to load models: {error}", { error: (e as Error).message }));
    } finally {
      setLoadingModels(false);
    }
  }

  return (
    <div className="grid gap-3 rounded-md border p-3">
      <div className="flex items-center justify-between gap-2">
        <Label>{t("ChatGPT account")}</Label>
        {loading && <Loader2Icon className="size-4 animate-spin text-muted-foreground" />}
      </div>

      {accounts.length > 0 && (
        <Select value={accountId} onValueChange={onAccountChange}>
          <SelectTrigger>
            <SelectValue placeholder={t("Choose an account")} />
          </SelectTrigger>
          <SelectContent>
            {accounts.map((a) => (
              <SelectItem key={a.id} value={a.id}>
                {a.email || t("Account #{id}", { id: a.id })}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}

      {selected && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          {statusBadge(selected)}
          {selected.last_error && <span className="text-muted-foreground text-xs">{selected.last_error}</span>}
          <div className="ml-auto flex gap-2">
            {selected.status === "plan_disabled" && (
              <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => signIn(selected, true)}>
                {t("Allow plan usage")}
              </Button>
            )}
            {selected.status === "needs_signin" && (
              <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => signIn(selected)}>
                {t("Sign in again")}
              </Button>
            )}
            {selected.status !== "needs_signin" && (
              <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => signOut(selected)}>
                <LogOutIcon /> {t("Sign out")}
              </Button>
            )}
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" size="sm" disabled={busy} onClick={() => signIn()}>
          {busy ? <Loader2Icon className="animate-spin" /> : <ExternalLinkIcon />}
          {accounts.length === 0 ? t("Sign in with ChatGPT") : t("Add another ChatGPT account")}
        </Button>
        {accountId && (
          <Button type="button" size="sm" variant="outline" disabled={loadingModels} onClick={loadModels}>
            {loadingModels ? <Loader2Icon className="animate-spin" /> : <RefreshCwIcon />}
            {t("Load models")}
          </Button>
        )}
      </div>

      {models.length > 0 && (
        <div className="flex max-h-40 flex-wrap gap-1 overflow-y-auto">
          {models.map((m) => (
            <Button
              key={m.id}
              type="button"
              size="sm"
              variant="secondary"
              className="font-mono text-xs"
              onClick={() => onPickModel(m.id)}
            >
              {m.name}
            </Button>
          ))}
        </div>
      )}

      {waiting && (
        <div className="grid gap-2">
          <p className="text-muted-foreground text-xs">
            {t(
              "Finish the sign-in in the new tab; this panel updates on its own. If that tab ends on an error page because this browser cannot reach 127.0.0.1 (ARTEX behind a reverse proxy or SSH), paste the full address from its address bar here:",
            )}
          </p>
          <div className="flex gap-2">
            <Input
              className="font-mono text-xs"
              placeholder="http://127.0.0.1:8787/auth/callback?code=…&state=…"
              value={paste}
              onChange={(e) => setPaste(e.target.value)}
              spellCheck={false}
            />
            <Button type="button" size="sm" variant="outline" disabled={busy || !paste.trim()} onClick={submitPaste}>
              {t("Submit")}
            </Button>
          </div>
        </div>
      )}

      <p className="text-muted-foreground text-xs">
        {t(
          "Uses your ChatGPT plan through OpenAI's Sign in with ChatGPT: requests are billed to the plan's usage limits, not to API credits. When the plan's limit is reached, tasks pause on this profile instead of switching to another one. Check usage at chatgpt.com/settings/usage.",
        )}
      </p>
    </div>
  );
}
