'use client';

interface DataPoint {
  label: string;
  value: number;
}

interface SimpleBarChartProps {
  data: DataPoint[];
  title?: string;
  height?: number;
  color?: string;
}

/**
 * Simple bar chart component using CSS (no external dependencies)
 */
export function SimpleBarChart({
  data,
  title,
  height = 200,
  color = '#3b82f6',
}: SimpleBarChartProps) {
  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center" style={{ height }}>
        <p className="text-muted-foreground">No data</p>
      </div>
    );
  }

  const maxValue = Math.max(...data.map((d) => d.value), 1);

  return (
    <div>
      {title && <h4 className="font-medium mb-4">{title}</h4>}
      <div className="flex items-end gap-1" style={{ height }}>
        {data.map((point, i) => (
          <div key={i} className="flex-1 flex flex-col items-center">
            <div
              className="w-full rounded-t transition-all hover:opacity-80"
              style={{
                height: `${(point.value / maxValue) * 100}%`,
                minHeight: point.value > 0 ? 4 : 0,
                backgroundColor: color,
              }}
              title={`${point.label}: ${point.value}`}
            />
            <span className="text-xs text-muted-foreground mt-1 truncate w-full text-center">
              {point.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

interface SimplePieChartProps {
  data: DataPoint[];
  title?: string;
  size?: number;
  colors?: string[];
}

/**
 * Simple pie/donut chart using CSS conic-gradient
 */
export function SimplePieChart({
  data,
  title,
  size = 200,
  colors = ['#3b82f6', '#f59e0b', '#ef4444', '#10b981', '#8b5cf6'],
}: SimplePieChartProps) {
  const total = data.reduce((sum, d) => sum + d.value, 0);

  if (total === 0) {
    return (
      <div className="flex items-center justify-center" style={{ width: size, height: size }}>
        <p className="text-muted-foreground">No data</p>
      </div>
    );
  }

  // Build conic gradient
  let gradientParts: string[] = [];
  let currentPercent = 0;

  data.forEach((point, i) => {
    const percent = (point.value / total) * 100;
    const color = colors[i % colors.length];
    gradientParts.push(`${color} ${currentPercent}% ${currentPercent + percent}%`);
    currentPercent += percent;
  });

  const gradient = `conic-gradient(${gradientParts.join(', ')})`;

  return (
    <div className="flex flex-col items-center">
      {title && <h4 className="font-medium mb-4">{title}</h4>}
      <div className="relative" style={{ width: size, height: size }}>
        <div
          className="rounded-full"
          style={{
            width: size,
            height: size,
            background: gradient,
          }}
        />
        {/* Center hole for donut effect */}
        <div
          className="absolute bg-white rounded-full"
          style={{
            width: size * 0.6,
            height: size * 0.6,
            top: size * 0.2,
            left: size * 0.2,
          }}
        />
        {/* Center text */}
        <div
          className="absolute inset-0 flex items-center justify-center"
          style={{ fontSize: size * 0.12 }}
        >
          <span className="font-bold">{total}</span>
        </div>
      </div>
      {/* Legend */}
      <div className="mt-4 flex flex-wrap justify-center gap-3">
        {data.map((point, i) => (
          <div key={i} className="flex items-center gap-1 text-sm">
            <div
              className="w-3 h-3 rounded-sm"
              style={{ backgroundColor: colors[i % colors.length] }}
            />
            <span>{point.label}</span>
            <span className="text-muted-foreground">({point.value})</span>
          </div>
        ))}
      </div>
    </div>
  );
}

interface SparklineProps {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
}

/**
 * Simple sparkline using SVG
 */
export function Sparkline({
  data,
  width = 100,
  height = 30,
  color = '#3b82f6',
}: SparklineProps) {
  if (data.length < 2) {
    return <div style={{ width, height }} />;
  }

  const maxValue = Math.max(...data, 1);
  const minValue = Math.min(...data, 0);
  const range = maxValue - minValue || 1;

  const points = data.map((value, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - ((value - minValue) / range) * height;
    return `${x},${y}`;
  });

  return (
    <svg width={width} height={height}>
      <polyline
        points={points.join(' ')}
        fill="none"
        stroke={color}
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

interface TrendIndicatorProps {
  current: number;
  previous: number;
  suffix?: string;
}

/**
 * Show trend with arrow and percentage
 */
export function TrendIndicator({ current, previous, suffix = '' }: TrendIndicatorProps) {
  if (previous === 0) {
    return <span className="text-sm text-muted-foreground">--</span>;
  }

  const change = ((current - previous) / previous) * 100;
  const isPositive = change > 0;
  const isNeutral = change === 0;

  return (
    <span
      className={`text-sm flex items-center gap-1 ${
        isNeutral ? 'text-gray-500' : isPositive ? 'text-red-600' : 'text-green-600'
      }`}
    >
      {!isNeutral && (
        <svg
          className={`w-4 h-4 ${isPositive ? '' : 'rotate-180'}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
        </svg>
      )}
      {Math.abs(change).toFixed(1)}%{suffix}
    </span>
  );
}
