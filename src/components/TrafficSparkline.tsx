interface Props {
  values: readonly number[];
  /** CSS color string. */
  stroke: string;
  /** Optional CSS height override. */
  height?: number;
}

/**
 * Tiny inline-SVG sparkline. Auto-scales to the local max so traffic spikes
 * stay visible. Pure: no state, no animation — re-render whenever values
 * change.
 */
export function TrafficSparkline({ values, stroke, height = 32 }: Props) {
  if (values.length < 2) return <svg className="spark" />;
  const max = Math.max(1, ...values);
  const width = 200;
  const step = width / (values.length - 1);
  const points = values
    .map((v, i) => `${i * step},${height - (v / max) * height}`)
    .join(" ");
  return (
    <svg
      className="spark"
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
    >
      <polyline
        fill="none"
        stroke={stroke}
        strokeWidth={1.5}
        strokeLinejoin="round"
        strokeLinecap="round"
        points={points}
      />
    </svg>
  );
}
