'use client';

import { useState, useRef, useEffect } from 'react';
import { useTenant } from '@/lib/auth/tenant-context';
import clsx from 'clsx';

export function TenantSwitcher() {
  const { currentTenant, availableTenants, setCurrentTenant, isLoadingTenants } = useTenant();
  const [isOpen, setIsOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const dropdownRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
        setSearchQuery('');
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Focus input when dropdown opens
  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  const filteredTenants = availableTenants.filter((tenant) =>
    tenant.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    tenant.domain?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleSelect = (tenant: typeof currentTenant) => {
    if (tenant) {
      setCurrentTenant(tenant);
      setIsOpen(false);
      setSearchQuery('');
    }
  };

  if (!currentTenant) {
    return (
      <div className="h-10 w-48 animate-pulse rounded-lg bg-gray-200" />
    );
  }

  return (
    <div ref={dropdownRef} className="relative" data-testid="tenant-switcher">
      {/* Trigger Button */}
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
        data-testid="tenant-switcher-trigger"
      >
        <div className="flex h-6 w-6 items-center justify-center rounded bg-blue-600 text-xs font-medium text-white">
          {currentTenant.name.charAt(0).toUpperCase()}
        </div>
        <span className="max-w-[150px] truncate font-medium" data-testid="current-tenant">
          {currentTenant.name}
        </span>
        <ChevronDownIcon className={clsx('h-4 w-4 text-gray-400 transition-transform', isOpen && 'rotate-180')} />
      </button>

      {/* Dropdown */}
      {isOpen && (
        <div className="absolute left-0 top-full z-50 mt-2 w-72 rounded-lg border border-gray-200 bg-white shadow-lg">
          {/* Search Input */}
          <div className="border-b border-gray-100 p-2">
            <input
              ref={inputRef}
              type="text"
              placeholder="Search tenants..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {/* Tenant List */}
          <div className="max-h-64 overflow-auto p-2">
            {isLoadingTenants ? (
              <div className="flex items-center justify-center py-4">
                <div className="h-5 w-5 animate-spin rounded-full border-2 border-blue-600 border-t-transparent" />
              </div>
            ) : filteredTenants.length === 0 ? (
              <div className="py-4 text-center text-sm text-gray-500">
                No tenants found
              </div>
            ) : (
              filteredTenants.map((tenant) => (
                <button
                  key={tenant.id}
                  onClick={() => handleSelect(tenant)}
                  className={clsx(
                    'flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors',
                    tenant.id === currentTenant.id
                      ? 'bg-blue-50 text-blue-700'
                      : 'hover:bg-gray-100'
                  )}
                >
                  <div className={clsx(
                    'flex h-8 w-8 items-center justify-center rounded text-xs font-medium text-white',
                    tenant.id === currentTenant.id ? 'bg-blue-600' : 'bg-gray-500'
                  )}>
                    {tenant.name.charAt(0).toUpperCase()}
                  </div>
                  <div className="flex-1 truncate">
                    <div className="font-medium">{tenant.name}</div>
                    {tenant.domain && (
                      <div className="text-xs text-gray-500">{tenant.domain}</div>
                    )}
                  </div>
                  {tenant.id === currentTenant.id && (
                    <CheckIcon className="h-4 w-4 text-blue-600" />
                  )}
                </button>
              ))
            )}
          </div>

          {/* Add Tenant Link (for MSP admins) */}
          <div className="border-t border-gray-100 p-2">
            <a
              href="/dashboard/tenants/new"
              className="flex items-center gap-2 rounded-md px-3 py-2 text-sm text-blue-600 hover:bg-blue-50"
            >
              <PlusIcon className="h-4 w-4" />
              Add new tenant
            </a>
          </div>
        </div>
      )}
    </div>
  );
}

// Icons
function ChevronDownIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
    </svg>
  );
}

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  );
}

function PlusIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
    </svg>
  );
}
