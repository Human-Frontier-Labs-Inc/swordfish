'use client';

import { createContext, useContext, useState, useCallback, useEffect, ReactNode } from 'react';
import { useOrganization, useOrganizationList, useUser } from '@clerk/nextjs';

// Role types matching our database schema
export type UserRole = 'msp_admin' | 'tenant_admin' | 'analyst' | 'viewer';

interface TenantInfo {
  id: string;
  clerkOrgId: string;
  name: string;
  domain: string | null;
  plan: 'starter' | 'pro' | 'enterprise';
}

interface TenantContextValue {
  // Current tenant
  currentTenant: TenantInfo | null;
  setCurrentTenant: (tenant: TenantInfo) => void;

  // Available tenants (for MSP users)
  availableTenants: TenantInfo[];
  isLoadingTenants: boolean;

  // User role
  userRole: UserRole;
  isMspUser: boolean;

  // Permissions
  canManageTenant: boolean;
  canViewAllTenants: boolean;
  canManagePolicies: boolean;
  canReleaseQuarantine: boolean;
}

const TenantContext = createContext<TenantContextValue | null>(null);

interface TenantProviderProps {
  children: ReactNode;
}

export function TenantProvider({ children }: TenantProviderProps) {
  const { user } = useUser();
  const { organization, membership } = useOrganization();
  const { userMemberships, isLoaded } = useOrganizationList({
    userMemberships: { infinite: true },
  });

  const [currentTenant, setCurrentTenantState] = useState<TenantInfo | null>(null);
  const [availableTenants, setAvailableTenants] = useState<TenantInfo[]>([]);
  const [isLoadingTenants, setIsLoadingTenants] = useState(true);

  // Derive user role from Clerk organization membership
  const userRole: UserRole = (() => {
    const clerkRole = membership?.role;

    // Map Clerk roles to our internal roles
    switch (clerkRole) {
      case 'org:admin': {
        // Check if user is part of an MSP organization
        const isMsp = organization?.publicMetadata?.isMsp === true;
        return isMsp ? 'msp_admin' : 'tenant_admin';
      }
      case 'org:member':
        return 'analyst';
      default:
        return 'viewer';
    }
  })();

  const isMspUser = userRole === 'msp_admin';

  // Load available tenants
  useEffect(() => {
    if (!isLoaded || !user) return;

    const loadTenants = async () => {
      setIsLoadingTenants(true);

      try {
        // For MSP users, fetch all accessible tenants from API
        if (isMspUser) {
          const response = await fetch('/api/tenants');
          if (response.ok) {
            const tenants = await response.json();
            setAvailableTenants(tenants);
          }
        } else if (organization) {
          // For regular users in an org, use their current org
          const tenant: TenantInfo = {
            id: organization.id,
            clerkOrgId: organization.id,
            name: organization.name,
            domain: (organization.publicMetadata?.domain as string) || null,
            plan: (organization.publicMetadata?.plan as TenantInfo['plan']) || 'starter',
          };
          setAvailableTenants([tenant]);
        } else {
          // For personal users (no org), create a personal tenant
          const personalTenant: TenantInfo = {
            id: `personal_${user.id}`,
            clerkOrgId: user.id,
            name: user.firstName ? `${user.firstName}'s Workspace` : 'Personal Workspace',
            domain: user.primaryEmailAddress?.emailAddress?.split('@')[1] || null,
            plan: 'starter',
          };
          setAvailableTenants([personalTenant]);
        }
      } catch (error) {
        console.error('Failed to load tenants:', error);
      } finally {
        setIsLoadingTenants(false);
      }
    };

    loadTenants();
  }, [isLoaded, user, organization, isMspUser]);

  // Set current tenant when org changes or for personal users
  useEffect(() => {
    if (currentTenant) return; // Already have a tenant

    if (organization) {
      setCurrentTenantState({
        id: organization.id,
        clerkOrgId: organization.id,
        name: organization.name,
        domain: (organization.publicMetadata?.domain as string) || null,
        plan: (organization.publicMetadata?.plan as TenantInfo['plan']) || 'starter',
      });
    } else if (isLoaded && user && !organization) {
      // Personal user without an org - create personal tenant
      setCurrentTenantState({
        id: `personal_${user.id}`,
        clerkOrgId: user.id,
        name: user.firstName ? `${user.firstName}'s Workspace` : 'Personal Workspace',
        domain: user.primaryEmailAddress?.emailAddress?.split('@')[1] || null,
        plan: 'starter',
      });
    }
  }, [organization, currentTenant, isLoaded, user]);

  // Persist selected tenant to localStorage
  const setCurrentTenant = useCallback((tenant: TenantInfo) => {
    setCurrentTenantState(tenant);
    localStorage.setItem('swordfish_current_tenant', JSON.stringify(tenant));
  }, []);

  // Restore tenant from localStorage on mount
  useEffect(() => {
    const stored = localStorage.getItem('swordfish_current_tenant');
    if (stored && isMspUser) {
      try {
        const tenant = JSON.parse(stored);
        setCurrentTenantState(tenant);
      } catch {
        // Invalid stored data, ignore
      }
    }
  }, [isMspUser]);

  // Compute permissions based on role
  const canManageTenant = userRole === 'msp_admin' || userRole === 'tenant_admin';
  const canViewAllTenants = userRole === 'msp_admin';
  const canManagePolicies = userRole === 'msp_admin' || userRole === 'tenant_admin';
  const canReleaseQuarantine = userRole !== 'viewer';

  const value: TenantContextValue = {
    currentTenant,
    setCurrentTenant,
    availableTenants,
    isLoadingTenants,
    userRole,
    isMspUser,
    canManageTenant,
    canViewAllTenants,
    canManagePolicies,
    canReleaseQuarantine,
  };

  return (
    <TenantContext.Provider value={value}>
      {children}
    </TenantContext.Provider>
  );
}

export function useTenant() {
  const context = useContext(TenantContext);
  if (!context) {
    throw new Error('useTenant must be used within a TenantProvider');
  }
  return context;
}

// Hook for checking specific permissions
export function usePermission(permission: keyof Pick<
  TenantContextValue,
  'canManageTenant' | 'canViewAllTenants' | 'canManagePolicies' | 'canReleaseQuarantine'
>) {
  const tenant = useTenant();
  return tenant[permission];
}
