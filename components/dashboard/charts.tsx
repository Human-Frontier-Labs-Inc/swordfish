'use client';

/**
 * Dashboard Charts Components
 * Reusable chart components for analytics visualization
 */

import { useMemo } from 'react';

// ============================================
// Time Series Line Chart
// ============================================

interface TimeSeriesPoint {
  date: string;
  value: number;
  label?: string;
}

interface LineChartProps {
  data: TimeSeriesPoint[];
  height?: number;
  color?: string;
  showGrid?: boolean;
  showLabels?: boolean;
  title?: string;
}

export function LineChart({
  data,
  height = 200,
  color = '#3b82f6',
  showGrid = true,
  showLabels = true,
  title,
}: LineChartProps) {
  const chartData = useMemo(() => {
    if (data.length === 0) return { points: '', max: 0, min: 0 };

    const values = data.map((d) => d.value);
    const max = Math.max(...values, 1);
    const min = Math.min(...values, 0);
    const range = max - min || 1;

    const width = 100;
    const h = height - 40; // Leave room for labels

    const points = data
      .map((d, i) => {
        const x = (i / (data.length - 1 || 1)) * width;
        const y = h - ((d.value - min) / range) * h;
        return `${x},${y}`;
      })
      .join(' ');

    return { points, max, min };
  }, [data, height]);

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400">
        No data available
      </div>
    );
  }

  return (
    <div className="w-full" style={{ height }}>
      {title && <div className="text-sm font-medium text-gray-600 mb-2">{title}</div>}
      <svg viewBox={`0 0 100 ${height - 20}`} className="w-full h-full" preserveAspectRatio="none">
        {/* Grid lines */}
        {showGrid && (
          <g className="text-gray-200">
            {[0, 25, 50, 75, 100].map((y) => (
              <line
                key={y}
                x1="0"
                y1={((height - 40) * y) / 100}
                x2="100"
                y2={((height - 40) * y) / 100}
                stroke="currentColor"
                strokeWidth="0.2"
              />
            ))}
          </g>
        )}

        {/* Area fill */}
        <polygon
          points={`0,${height - 40} ${chartData.points} 100,${height - 40}`}
          fill={color}
          fillOpacity="0.1"
        />

        {/* Line */}
        <polyline
          points={chartData.points}
          fill="none"
          stroke={color}
          strokeWidth="0.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />

        {/* Data points */}
        {data.map((d, i) => {
          const x = (i / (data.length - 1 || 1)) * 100;
          const y =
            (height - 40) -
            ((d.value - chartData.min) / (chartData.max - chartData.min || 1)) * (height - 40);
          return (
            <circle
              key={i}
              cx={x}
              cy={y}
              r="1"
              fill={color}
              className="hover:r-2 cursor-pointer"
            >
              <title>
                {d.date}: {d.value}
              </title>
            </circle>
          );
        })}
      </svg>

      {/* X-axis labels */}
      {showLabels && data.length > 0 && (
        <div className="flex justify-between text-xs text-gray-500 mt-1">
          <span>{data[0]?.date}</span>
          <span>{data[data.length - 1]?.date}</span>
        </div>
      )}
    </div>
  );
}

// ============================================
// Bar Chart
// ============================================

interface BarChartProps {
  data: Array<{ label: string; value: number; color?: string }>;
  height?: number;
  orientation?: 'vertical' | 'horizontal';
  showValues?: boolean;
}

export function BarChart({
  data,
  height = 200,
  orientation = 'vertical',
  showValues = true,
}: BarChartProps) {
  const maxValue = Math.max(...data.map((d) => d.value), 1);

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400">
        No data available
      </div>
    );
  }

  if (orientation === 'horizontal') {
    return (
      <div className="space-y-2" style={{ minHeight: height }}>
        {data.map((item, i) => (
          <div key={i} className="flex items-center gap-2">
            <div className="w-24 text-sm text-gray-600 truncate">{item.label}</div>
            <div className="flex-1 bg-gray-100 rounded-full h-4 overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${(item.value / maxValue) * 100}%`,
                  backgroundColor: item.color || '#3b82f6',
                }}
              />
            </div>
            {showValues && <div className="text-sm font-medium w-12 text-right">{item.value}</div>}
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="flex items-end justify-around gap-2" style={{ height }}>
      {data.map((item, i) => (
        <div key={i} className="flex flex-col items-center flex-1 max-w-16">
          {showValues && (
            <div className="text-xs font-medium text-gray-600 mb-1">{item.value}</div>
          )}
          <div
            className="w-full rounded-t transition-all duration-500"
            style={{
              height: `${(item.value / maxValue) * (height - 40)}px`,
              backgroundColor: item.color || '#3b82f6',
              minHeight: item.value > 0 ? '4px' : '0',
            }}
          />
          <div className="text-xs text-gray-500 mt-1 text-center truncate w-full">
            {item.label}
          </div>
        </div>
      ))}
    </div>
  );
}

// ============================================
// Pie / Donut Chart
// ============================================

interface PieChartProps {
  data: Array<{ label: string; value: number; color: string }>;
  size?: number;
  donut?: boolean;
  showLegend?: boolean;
}

export function PieChart({ data, size = 200, donut = true, showLegend = true }: PieChartProps) {
  const total = data.reduce((sum, d) => sum + d.value, 0);

  const segments = useMemo(() => {
    if (total === 0) return [];

    let currentAngle = -90; // Start from top
    const radius = 45;
    const innerRadius = donut ? 25 : 0;

    return data.map((item) => {
      const angle = (item.value / total) * 360;
      const startAngle = currentAngle;
      const endAngle = currentAngle + angle;
      currentAngle = endAngle;

      // Convert angles to radians
      const startRad = (startAngle * Math.PI) / 180;
      const endRad = (endAngle * Math.PI) / 180;

      // Calculate arc path
      const x1 = 50 + radius * Math.cos(startRad);
      const y1 = 50 + radius * Math.sin(startRad);
      const x2 = 50 + radius * Math.cos(endRad);
      const y2 = 50 + radius * Math.sin(endRad);

      const largeArc = angle > 180 ? 1 : 0;

      let path: string;
      if (donut) {
        const ix1 = 50 + innerRadius * Math.cos(startRad);
        const iy1 = 50 + innerRadius * Math.sin(startRad);
        const ix2 = 50 + innerRadius * Math.cos(endRad);
        const iy2 = 50 + innerRadius * Math.sin(endRad);

        path = `M ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2} L ${ix2} ${iy2} A ${innerRadius} ${innerRadius} 0 ${largeArc} 0 ${ix1} ${iy1} Z`;
      } else {
        path = `M 50 50 L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2} Z`;
      }

      return {
        ...item,
        path,
        percentage: ((item.value / total) * 100).toFixed(1),
      };
    });
  }, [data, total, donut]);

  if (total === 0) {
    return (
      <div className="flex items-center justify-center" style={{ width: size, height: size }}>
        <span className="text-gray-400">No data</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-4">
      <svg viewBox="0 0 100 100" style={{ width: size, height: size }}>
        {segments.map((segment, i) => (
          <path
            key={i}
            d={segment.path}
            fill={segment.color}
            className="hover:opacity-80 transition-opacity cursor-pointer"
          >
            <title>
              {segment.label}: {segment.value} ({segment.percentage}%)
            </title>
          </path>
        ))}
        {donut && (
          <text x="50" y="50" textAnchor="middle" dominantBaseline="middle" className="text-xs">
            <tspan className="font-bold text-lg">{total}</tspan>
          </text>
        )}
      </svg>

      {showLegend && (
        <div className="space-y-1">
          {segments.map((segment, i) => (
            <div key={i} className="flex items-center gap-2 text-sm">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: segment.color }}
              />
              <span className="text-gray-600">{segment.label}</span>
              <span className="font-medium">{segment.percentage}%</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ============================================
// Stat Trend Indicator
// ============================================

interface TrendIndicatorProps {
  value: number;
  previousValue: number;
  format?: 'percent' | 'number';
  goodDirection?: 'up' | 'down';
}

export function TrendIndicator({
  value,
  previousValue,
  format = 'percent',
  goodDirection = 'up',
}: TrendIndicatorProps) {
  const change = previousValue > 0 ? ((value - previousValue) / previousValue) * 100 : 0;
  const isPositive = change > 0;
  const isGood = goodDirection === 'up' ? isPositive : !isPositive;

  const displayChange = format === 'percent' ? `${Math.abs(change).toFixed(1)}%` : Math.abs(value - previousValue);

  if (change === 0) {
    return <span className="text-gray-400 text-sm">No change</span>;
  }

  return (
    <span
      className={`inline-flex items-center text-sm font-medium ${
        isGood ? 'text-green-600' : 'text-red-600'
      }`}
    >
      {isPositive ? (
        <svg className="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" />
        </svg>
      ) : (
        <svg className="w-4 h-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
        </svg>
      )}
      {displayChange}
    </span>
  );
}

// ============================================
// Sparkline (Mini Chart)
// ============================================

interface SparklineProps {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
}

export function Sparkline({ data, width = 100, height = 30, color = '#3b82f6' }: SparklineProps) {
  if (data.length === 0) return null;

  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const range = max - min || 1;

  const points = data
    .map((value, i) => {
      const x = (i / (data.length - 1 || 1)) * width;
      const y = height - ((value - min) / range) * height;
      return `${x},${y}`;
    })
    .join(' ');

  return (
    <svg width={width} height={height} className="inline-block">
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// ============================================
// Progress Ring
// ============================================

interface ProgressRingProps {
  value: number;
  max?: number;
  size?: number;
  strokeWidth?: number;
  color?: string;
  label?: string;
}

export function ProgressRing({
  value,
  max = 100,
  size = 80,
  strokeWidth = 8,
  color = '#3b82f6',
  label,
}: ProgressRingProps) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const percentage = Math.min((value / max) * 100, 100);
  const offset = circumference - (percentage / 100) * circumference;

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={size} height={size}>
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="#e5e7eb"
          strokeWidth={strokeWidth}
        />
        {/* Progress circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          className="transition-all duration-500"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-lg font-bold">{Math.round(percentage)}%</span>
        {label && <span className="text-xs text-gray-500">{label}</span>}
      </div>
    </div>
  );
}

// ============================================
// Heatmap
// ============================================

interface HeatmapProps {
  data: Array<{ x: number; y: number; value: number }>;
  xLabels?: string[];
  yLabels?: string[];
  colorScale?: string[];
}

export function Heatmap({
  data,
  xLabels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
  yLabels = Array.from({ length: 24 }, (_, i) => `${i}:00`),
  colorScale = ['#f3f4f6', '#dbeafe', '#93c5fd', '#3b82f6', '#1d4ed8'],
}: HeatmapProps) {
  const maxValue = Math.max(...data.map((d) => d.value), 1);

  const getColor = (value: number) => {
    const index = Math.floor((value / maxValue) * (colorScale.length - 1));
    return colorScale[Math.min(index, colorScale.length - 1)];
  };

  // Create a map for quick lookup
  const valueMap = new Map(data.map((d) => [`${d.x},${d.y}`, d.value]));

  return (
    <div className="overflow-auto">
      <div className="inline-block">
        {/* Y-axis labels */}
        <div className="flex">
          <div className="w-12" />
          {xLabels.map((label, i) => (
            <div key={i} className="w-8 text-xs text-center text-gray-500">
              {label}
            </div>
          ))}
        </div>

        {/* Grid */}
        {yLabels.map((yLabel, y) => (
          <div key={y} className="flex">
            <div className="w-12 text-xs text-gray-500 text-right pr-2 flex items-center justify-end">
              {y % 4 === 0 ? yLabel : ''}
            </div>
            {xLabels.map((_, x) => {
              const value = valueMap.get(`${x},${y}`) || 0;
              return (
                <div
                  key={x}
                  className="w-8 h-3 m-0.5 rounded-sm cursor-pointer hover:ring-2 hover:ring-blue-400"
                  style={{ backgroundColor: getColor(value) }}
                  title={`${xLabels[x]} ${yLabel}: ${value}`}
                />
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}
