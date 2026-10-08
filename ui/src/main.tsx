import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { AuthProvider, useAuth } from "@/lib/auth";
import { I18nProvider } from "@/lib/i18n";
import { PrefsProvider, usePrefs } from "@/lib/prefs";
import { router } from "@/router";
import "@/styles.css";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false, staleTime: 5_000 } },
});

function Routed() {
  const auth = useAuth();
  return <RouterProvider router={router} context={{ auth }} />;
}

function Localized() {
  const { lang } = usePrefs();
  return (
    <I18nProvider lang={lang}>
      <AuthProvider>
        <Routed />
      </AuthProvider>
    </I18nProvider>
  );
}

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <PrefsProvider>
          <Localized />
        </PrefsProvider>
      </QueryClientProvider>
    </StrictMode>,
  );
}
