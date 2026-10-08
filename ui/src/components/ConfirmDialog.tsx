import * as Dialog from "@radix-ui/react-dialog";
import type { ReactNode } from "react";
import { useI18n } from "@/lib/i18n";

interface Props {
  open: boolean;
  title: string;
  body: ReactNode;
  confirmLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({ open, title, body, confirmLabel, onConfirm, onCancel }: Props) {
  const { t } = useI18n();
  return (
    <Dialog.Root open={open} onOpenChange={(next) => { if (!next) onCancel(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-ink/30" />
        <Dialog.Content className="fixed left-1/2 top-1/3 w-96 -translate-x-1/2 rounded border border-line bg-paper p-4 shadow-lg">
          <Dialog.Title className="text-sm font-medium">{title}</Dialog.Title>
          <Dialog.Description className="mt-2 text-xs text-ink-soft">{body}</Dialog.Description>
          <div className="mt-4 flex justify-end gap-2">
            <button type="button" onClick={onCancel} className="rounded border border-line px-2 py-1 text-xs">
              {t("common.cancel")}
            </button>
            <button type="button" onClick={onConfirm} className="rounded bg-ink px-2 py-1 text-xs text-paper">
              {confirmLabel ?? t("common.confirm")}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
