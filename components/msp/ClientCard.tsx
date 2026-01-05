'use client';

import Link from 'next/link';
import { Building2, Users, Mail, Shield, AlertTriangle, TrendingUp, TrendingDown } from 'lucide-react';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

export interface ClientData {
  id: string;
  name: string;
  domain: string | null;
  plan: 'starter' | 'pro' | 'enterprise';
  status: 'active' | 'suspended' | 'pending';
  userCount: number;
  emailsProcessed: number;
  emailsTrend: number; // percentage change vs previous period
  threatsBlocked: number;
  threatsTrend: number;
  quarantinePending: number;
  lastActivityAt: string | null;
  healthScore: number; // 0-100
  integrationStatus: 'connected' | 'disconnected' | 'error';
}

interface ClientCardProps {
  client: ClientData;
  onSelect?: (clientId: string) => void;
  selected?: boolean;
}

export function ClientCard({ client, onSelect, selected }: ClientCardProps) {
  const statusColors = {
    active: 'bg-green-100 text-green-700 border-green-200',
    suspended: 'bg-red-100 text-red-700 border-red-200',
    pending: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  };

  const planColors = {
    starter: 'bg-gray-100 text-gray-700',
    pro: 'bg-blue-100 text-blue-700',
    enterprise: 'bg-purple-100 text-purple-700',
  };

  const healthColor =
    client.healthScore >= 80
      ? 'text-green-600'
      : client.healthScore >= 60
      ? 'text-yellow-600'
      : 'text-red-600';

  return (
    <Card
      className={`cursor-pointer transition-all hover:shadow-md ${
        selected ? 'ring-2 ring-blue-500' : ''
      }`}
      onClick={() => onSelect?.(client.id)}
      data-testid="client-card"
    >
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gray-100 rounded-lg">
              <Building2 className="h-5 w-5 text-gray-600" />
            </div>
            <div>
              <CardTitle className="text-lg">{client.name}</CardTitle>
              {client.domain && (
                <p className="text-sm text-muted-foreground">{client.domain}</p>
              )}
            </div>
          </div>
          <div className="flex gap-2">
            <Badge className={planColors[client.plan]}>
              {client.plan.charAt(0).toUpperCase() + client.plan.slice(1)}
            </Badge>
            <Badge className={statusColors[client.status]}>
              {client.status.charAt(0).toUpperCase() + client.status.slice(1)}
            </Badge>
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Stats Grid */}
        <div className="grid grid-cols-3 gap-4">
          <StatItem
            icon={<Users className="h-4 w-4" />}
            label="Users"
            value={client.userCount}
          />
          <StatItem
            icon={<Mail className="h-4 w-4" />}
            label="Emails (30d)"
            value={formatNumber(client.emailsProcessed)}
            trend={client.emailsTrend}
          />
          <StatItem
            icon={<Shield className="h-4 w-4" />}
            label="Threats"
            value={client.threatsBlocked}
            trend={client.threatsTrend}
            trendInverse
          />
        </div>

        {/* Alerts */}
        {client.quarantinePending > 0 && (
          <div className="flex items-center gap-2 p-2 bg-yellow-50 rounded-lg border border-yellow-200">
            <AlertTriangle className="h-4 w-4 text-yellow-600" />
            <span className="text-sm text-yellow-700">
              {client.quarantinePending} items pending review
            </span>
          </div>
        )}

        {/* Health & Integration Status */}
        <div className="flex items-center justify-between pt-2 border-t">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Health:</span>
            <span className={`font-semibold ${healthColor}`}>
              {client.healthScore}%
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span
              className={`h-2 w-2 rounded-full ${
                client.integrationStatus === 'connected'
                  ? 'bg-green-500'
                  : client.integrationStatus === 'error'
                  ? 'bg-red-500'
                  : 'bg-gray-400'
              }`}
            />
            <span className="text-sm text-muted-foreground capitalize">
              {client.integrationStatus}
            </span>
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-2 pt-2">
          <Button variant="outline" size="sm" asChild className="flex-1">
            <Link href={`/admin/tenants/${client.id}`}>View Details</Link>
          </Button>
          <Button variant="outline" size="sm" asChild className="flex-1">
            <Link href={`/dashboard?tenant=${client.id}`}>Switch To</Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function StatItem({
  icon,
  label,
  value,
  trend,
  trendInverse,
}: {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  trend?: number;
  trendInverse?: boolean;
}) {
  const trendColor =
    trend !== undefined
      ? trendInverse
        ? trend > 0
          ? 'text-red-500'
          : 'text-green-500'
        : trend > 0
        ? 'text-green-500'
        : 'text-red-500'
      : '';

  return (
    <div className="text-center">
      <div className="flex items-center justify-center gap-1 text-muted-foreground mb-1">
        {icon}
        <span className="text-xs">{label}</span>
      </div>
      <div className="font-semibold">{value}</div>
      {trend !== undefined && (
        <div className={`flex items-center justify-center gap-1 text-xs ${trendColor}`}>
          {trend > 0 ? (
            <TrendingUp className="h-3 w-3" />
          ) : (
            <TrendingDown className="h-3 w-3" />
          )}
          <span>{Math.abs(trend)}%</span>
        </div>
      )}
    </div>
  );
}

function formatNumber(num: number): string {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toString();
}

export default ClientCard;
