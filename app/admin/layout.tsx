'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

interface AdminLayoutProps {
  children: React.ReactNode;
}

export default function AdminLayout({ children }: AdminLayoutProps) {
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null);
  const router = useRouter();

  useEffect(() => {
    checkAdminAccess();
  }, []);

  async function checkAdminAccess() {
    try {
      const response = await fetch('/api/admin/verify');
      if (response.ok) {
        setIsAdmin(true);
      } else {
        setIsAdmin(false);
        router.push('/dashboard');
      }
    } catch {
      setIsAdmin(false);
      router.push('/dashboard');
    }
  }

  if (isAdmin === null) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  if (!isAdmin) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Admin Header */}
      <header className="bg-gray-900 text-white">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/admin" className="font-bold text-lg">
              Swordfish Admin
            </Link>
            <span className="bg-red-500 text-xs px-2 py-1 rounded">MSP</span>
          </div>
          <nav className="flex items-center gap-6">
            <Link href="/admin" className="text-gray-300 hover:text-white text-sm">
              Dashboard
            </Link>
            <Link href="/admin/tenants" className="text-gray-300 hover:text-white text-sm">
              Tenants
            </Link>
            <Link href="/admin/users" className="text-gray-300 hover:text-white text-sm">
              Users
            </Link>
            <Link href="/admin/audit" className="text-gray-300 hover:text-white text-sm">
              Audit Log
            </Link>
            <Link href="/dashboard" className="text-gray-400 hover:text-white text-sm">
              Exit Admin
            </Link>
          </nav>
        </div>
      </header>

      {/* Admin Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        {children}
      </main>
    </div>
  );
}
