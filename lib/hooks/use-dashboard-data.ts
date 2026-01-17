'use client';

import { useState, useEffect, useCallback } from 'react';

interface DashboardStats {
  emailsScanned: number;
  threatsBlocked: number;
  quarantined: number;
  detectionRate: number;
  avgProcessingTimeMs: number;
  breakdown: {
    passed: number;
    suspicious: number;
    quarantined: number;
    blocked: number;
  };
  period: string;
}

interface Threat {
  id: string;
  type: string;
  subject: string;
  sender: string;
  verdict: string;
  score: number;
  detail: string;
  signalCount: number;
  timestamp: string;
}

interface QuarantinedEmail {
  id: string;
  verdictId: string;
  originalLocation: string;
  status: string;
  quarantinedAt: string;
  expiresAt: string;
}

interface UseDashboardDataReturn {
  stats: DashboardStats | null;
  threats: Threat[];
  quarantined: QuarantinedEmail[];
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

export function useDashboardData(): UseDashboardDataReturn {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [quarantined, setQuarantined] = useState<QuarantinedEmail[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      // Fetch all data in parallel
      const [statsRes, threatsRes, quarantineRes] = await Promise.all([
        fetch('/api/dashboard/stats'),
        fetch('/api/dashboard/threats?limit=50'),
        fetch('/api/dashboard/quarantine?limit=50'),
      ]);

      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      if (threatsRes.ok) {
        const threatsData = await threatsRes.json();
        setThreats(threatsData.threats || []);
      }

      if (quarantineRes.ok) {
        const quarantineData = await quarantineRes.json();
        setQuarantined(quarantineData.emails || []);
      }
    } catch (err) {
      console.error('Failed to fetch dashboard data:', err);
      setError(err instanceof Error ? err.message : 'Failed to load dashboard data');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return {
    stats,
    threats,
    quarantined,
    isLoading,
    error,
    refetch: fetchData,
  };
}

// Hook for real-time stats polling
export function useLiveStats(intervalMs: number = 30000) {
  const { stats, isLoading, error, refetch } = useDashboardData();

  useEffect(() => {
    const interval = setInterval(refetch, intervalMs);
    return () => clearInterval(interval);
  }, [refetch, intervalMs]);

  return { stats, isLoading, error };
}
