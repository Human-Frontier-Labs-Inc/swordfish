import { TenantProvider } from '@/lib/auth/tenant-context';
import { DashboardLayout } from '@/components/layout/dashboard-layout';

export default function DashboardRootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <TenantProvider>
      <DashboardLayout>{children}</DashboardLayout>
    </TenantProvider>
  );
}
