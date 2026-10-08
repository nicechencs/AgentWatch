import { useRef, useState } from "react";
import type { HistogramBucket } from "@/api/types";
import { nsToRfc3339 } from "@/lib/format";
import { useI18n } from "@/lib/i18n";

interface Props {
  buckets: HistogramBucket[];
  onSelect: (from: string, to: string) => void;
}

/**
 * Time density strip shared across in-session pages. Drag to set the from/to
 * window; spans that contain a gap are drawn in the gap colour (ui §2).
 */
export function DensityBar({ buckets, onSelect }: Props) {
  const { t } = useI18n();
  const ref = useRef<HTMLDivElement>(null);
  const [drag, setDrag] = useState<{ start: number; end: number } | null>(null);
  const max = Math.max(1, ...buckets.map((bucket) => bucket.count));

  if (buckets.length === 0) return null;

  const indexAt = (clientX: number) => {
    const rect = ref.current?.getBoundingClientRect();
    if (!rect || rect.width === 0) return 0;
    const ratio = Math.min(1, Math.max(0, (clientX - rect.left) / rect.width));
    return Math.min(buckets.length - 1, Math.floor(ratio * buckets.length));
  };

  const selection =
    drag === null
      ? null
      : {
          left: (Math.min(drag.start, drag.end) / buckets.length) * 100,
          width: (Math.abs(drag.end - drag.start) + 1) * (100 / buckets.length),
        };

  return (
    <div
      ref={ref}
      role="slider"
      aria-label={t("density.aria")}
      tabIndex={0}
      className="relative flex h-8 cursor-crosshair items-end gap-px border-b border-line bg-paper-sunken px-3"
      onPointerDown={(event) => {
        const index = indexAt(event.clientX);
        setDrag({ start: index, end: index });
        event.currentTarget.setPointerCapture(event.pointerId);
      }}
      onPointerMove={(event) => {
        if (drag) setDrag({ ...drag, end: indexAt(event.clientX) });
      }}
      onPointerUp={() => {
        if (!drag) return;
        const [a, b] = [Math.min(drag.start, drag.end), Math.max(drag.start, drag.end)];
        onSelect(nsToRfc3339(buckets[a].start_ns), nsToRfc3339(buckets[b].end_ns));
        setDrag(null);
      }}
    >
      {buckets.map((bucket, index) => (
        <span
          key={bucket.start_ns}
          title={bucket.gap ? t("density.gap") : String(bucket.count)}
          className={`flex-1 ${bucket.gap ? "bg-gap" : "bg-ink-soft"}`}
          style={{ height: `${Math.max(8, (bucket.count / max) * 100)}%` }}
          data-index={index}
        />
      ))}
      {selection ? (
        <span
          className="pointer-events-none absolute bottom-0 top-0 bg-accent/20 ring-1 ring-accent"
          style={{ left: `${selection.left}%`, width: `${selection.width}%` }}
        />
      ) : null}
    </div>
  );
}
