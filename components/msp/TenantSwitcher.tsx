'use client';

import { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Check, ChevronsUpDown, Building2, Plus } from 'lucide-react';

import { Button } from '@/components/ui/button';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { Badge } from '@/components/ui/badge';

export interface TenantOption {
  id: string;
  name: string;
  domain: string | null;
  plan: 'starter' | 'pro' | 'enterprise';
  role: 'owner' | 'admin' | 'analyst' | 'viewer';
}

interface TenantSwitcherProps {
  tenants: TenantOption[];
  currentTenantId: string | null;
  onSwitch: (tenantId: string) => void;
  isMSPUser?: boolean;
}

export function TenantSwitcher({
  tenants,
  currentTenantId,
  onSwitch,
  isMSPUser = false,
}: TenantSwitcherProps) {
  const [open, setOpen] = useState(false);
  const router = useRouter();

  const currentTenant = tenants.find((t) => t.id === currentTenantId);

  const handleSelect = (tenantId: string) => {
    if (tenantId !== currentTenantId) {
      onSwitch(tenantId);
    }
    setOpen(false);
  };

  const planColors = {
    starter: 'bg-gray-100 text-gray-600',
    pro: 'bg-blue-100 text-blue-600',
    enterprise: 'bg-purple-100 text-purple-600',
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className="w-[250px] justify-between"
        >
          <div className="flex items-center gap-2 truncate">
            <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" />
            <span className="truncate">
              {currentTenant?.name || 'Select organization...'}
            </span>
          </div>
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[250px] p-0" align="start">
        <Command>
          <CommandInput placeholder="Search organizations..." />
          <CommandList>
            <CommandEmpty>No organization found.</CommandEmpty>
            <CommandGroup heading="Organizations">
              {tenants.map((tenant) => (
                <CommandItem
                  key={tenant.id}
                  value={tenant.name}
                  onSelect={() => handleSelect(tenant.id)}
                  className="flex items-center justify-between"
                >
                  <div className="flex items-center gap-2 truncate">
                    <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" />
                    <div className="truncate">
                      <p className="truncate font-medium">{tenant.name}</p>
                      {tenant.domain && (
                        <p className="text-xs text-muted-foreground truncate">
                          {tenant.domain}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={`text-xs ${planColors[tenant.plan]}`}>
                      {tenant.plan}
                    </Badge>
                    {tenant.id === currentTenantId && (
                      <Check className="h-4 w-4 text-primary" />
                    )}
                  </div>
                </CommandItem>
              ))}
            </CommandGroup>
            {isMSPUser && (
              <>
                <CommandSeparator />
                <CommandGroup>
                  <CommandItem
                    onSelect={() => {
                      setOpen(false);
                      router.push('/admin/tenants/new');
                    }}
                  >
                    <Plus className="mr-2 h-4 w-4" />
                    Add New Client
                  </CommandItem>
                </CommandGroup>
              </>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

/**
 * Hook to manage tenant context
 */
export function useTenantContext() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [currentTenantId, setCurrentTenantId] = useState<string | null>(null);
  const [tenants, setTenants] = useState<TenantOption[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check URL for tenant override
    const urlTenant = searchParams.get('tenant');
    if (urlTenant) {
      setCurrentTenantId(urlTenant);
    }

    // Load available tenants
    loadTenants();
  }, [searchParams]);

  async function loadTenants() {
    try {
      const response = await fetch('/api/msp/tenants');
      if (response.ok) {
        const data = await response.json();
        setTenants(data.tenants);
        if (!currentTenantId && data.tenants.length > 0) {
          setCurrentTenantId(data.defaultTenantId || data.tenants[0].id);
        }
      }
    } catch (error) {
      console.error('Failed to load tenants:', error);
    } finally {
      setLoading(false);
    }
  }

  function switchTenant(tenantId: string) {
    setCurrentTenantId(tenantId);
    // Update URL to reflect tenant switch
    const url = new URL(window.location.href);
    url.searchParams.set('tenant', tenantId);
    router.push(url.pathname + url.search);
  }

  return {
    currentTenantId,
    tenants,
    loading,
    switchTenant,
  };
}

export default TenantSwitcher;
