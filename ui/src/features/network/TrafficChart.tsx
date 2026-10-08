import { useEffect, useRef } from "react";
import { BarChart, LineChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import { init, use as registerCharts, type ECharts } from "echarts/core";
import { CanvasRenderer } from "echarts/renderers";
import type { TrafficSeries } from "@/api/types";
import { nsToDate } from "@/lib/format";

registerCharts([LineChart, BarChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

const PALETTE = ["#1f6f78", "#c47a3a", "#6b6e76", "#8a9a5b", "#7a5c8a", "#b4534d"];

interface Props {
  series: TrafficSeries;
  direction: "up" | "down";
  label: string;
}

/** Stacked area of payload bytes per bucket. Only the charts actually used are bundled. */
export function TrafficChart({ series, direction, label }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const chart = useRef<ECharts | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    chart.current = init(ref.current);
    const observer = new ResizeObserver(() => chart.current?.resize());
    observer.observe(ref.current);
    return () => {
      observer.disconnect();
      chart.current?.dispose();
    };
  }, []);

  useEffect(() => {
    const dark = document.documentElement.classList.contains("dark");
    const ink = dark ? "#e6e7ea" : "#1c1f24";
    const faint = dark ? "#787d86" : "#8a909a";
    chart.current?.setOption({
      color: PALETTE,
      textStyle: { fontFamily: "system-ui, sans-serif", fontSize: 11, color: ink },
      grid: { left: 48, right: 12, top: 28, bottom: 24 },
      legend: { top: 0, textStyle: { color: faint }, type: "scroll" },
      tooltip: { trigger: "axis" },
      xAxis: {
        type: "time",
        axisLabel: { color: faint },
        axisLine: { lineStyle: { color: faint } },
      },
      yAxis: { type: "value", axisLabel: { color: faint }, splitLine: { lineStyle: { color: dark ? "#363a42" : "#d6d6d2" } } },
      series: series.labels.map((name, index) => ({
        name,
        type: "line",
        stack: "traffic",
        areaStyle: { opacity: 0.35 },
        showSymbol: false,
        data: series.buckets.map((bucket) => [
          nsToDate(bucket.start_ns).getTime(),
          (direction === "up" ? bucket.values_up : bucket.values_down)[index] ?? 0,
        ]),
      })),
    });
  }, [series, direction]);

  return (
    <figure className="h-44">
      <figcaption className="sr-only">{label}</figcaption>
      <div ref={ref} className="h-full w-full" />
    </figure>
  );
}
