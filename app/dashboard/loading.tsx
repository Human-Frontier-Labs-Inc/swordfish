import { Skeleton } from '@/components/ui/skeleton';

export default function DashboardLoading() {
  return (
    <div className="space-y-6">
      {/* Page Header skeleton */}
      <div>
        <Skeleton className="h-8 w-48 dark:bg-slate-700" />
        <Skeleton className="mt-2 h-4 w-72 dark:bg-slate-700" />
      </div>

      {/* Stats Grid skeleton -- 4 cards */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="rounded-lg border-l-4 border-l-slate-300 bg-white p-6 shadow-sm dark:bg-slate-800 dark:border-l-slate-600"
          >
            <div className="flex items-center justify-between">
              <Skeleton className="h-4 w-28 dark:bg-slate-700" />
              <Skeleton className="h-10 w-10 rounded-lg dark:bg-slate-700" />
            </div>
            <Skeleton className="mt-4 h-8 w-20 dark:bg-slate-700" />
            <Skeleton className="mt-2 h-3 w-16 dark:bg-slate-700" />
          </div>
        ))}
      </div>

      {/* Main Content Grid skeleton */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Recent Threats skeleton -- 2 columns */}
        <div className="lg:col-span-2 rounded-lg bg-white p-6 shadow-sm dark:bg-slate-800">
          <div className="flex items-center gap-3 mb-4">
            <Skeleton className="h-6 w-36 dark:bg-slate-700" />
            <Skeleton className="h-5 w-12 rounded-full dark:bg-slate-700" />
          </div>
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-4 py-3 border-b border-slate-100 last:border-0 dark:border-slate-700/50">
                <Skeleton className="h-2.5 w-2.5 rounded-full flex-shrink-0 dark:bg-slate-700" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-4 w-3/4 dark:bg-slate-700" />
                  <Skeleton className="h-3 w-1/2 dark:bg-slate-700" />
                </div>
                <Skeleton className="h-6 w-20 rounded-full dark:bg-slate-700" />
              </div>
            ))}
          </div>
        </div>

        {/* Integration Status skeleton -- 1 column */}
        <div className="rounded-lg bg-white p-6 shadow-sm dark:bg-slate-800">
          <Skeleton className="h-6 w-40 mb-4 dark:bg-slate-700" />
          <div className="space-y-4">
            {Array.from({ length: 2 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3">
                <Skeleton className="h-10 w-10 rounded-lg dark:bg-slate-700" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-4 w-28 dark:bg-slate-700" />
                  <Skeleton className="h-3 w-20 dark:bg-slate-700" />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Actions skeleton */}
      <div className="rounded-lg bg-white p-6 shadow-sm dark:bg-slate-800">
        <Skeleton className="h-6 w-28 mb-4 dark:bg-slate-700" />
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="flex items-center gap-4 rounded-lg border border-slate-200 p-4 dark:border-slate-700">
              <Skeleton className="h-10 w-10 rounded-lg dark:bg-slate-700" />
              <div className="space-y-2">
                <Skeleton className="h-4 w-24 dark:bg-slate-700" />
                <Skeleton className="h-3 w-32 dark:bg-slate-700" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
