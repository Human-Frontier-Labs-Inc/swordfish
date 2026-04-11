import Link from 'next/link';

export default function NotFound(): React.ReactElement {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-slate-950 px-4">
      <div className="text-center max-w-md">
        {/* Shield logo */}
        <div className="mx-auto mb-8 w-20 h-20 relative">
          <svg
            viewBox="0 0 80 80"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            className="w-20 h-20"
            aria-hidden="true"
          >
            {/* Shield shape */}
            <path
              d="M40 4L10 18V38C10 56.78 22.88 74.12 40 78C57.12 74.12 70 56.78 70 38V18L40 4Z"
              className="fill-slate-200 dark:fill-slate-800 stroke-blue-500 dark:stroke-blue-400"
              strokeWidth="2"
            />
            {/* Swordfish "S" accent */}
            <path
              d="M40 24C34 24 30 28 30 32C30 36 34 38 40 40C46 42 50 44 50 48C50 52 46 56 40 56C34 56 30 52 30 48"
              className="stroke-blue-600 dark:stroke-blue-400"
              strokeWidth="3"
              strokeLinecap="round"
              fill="none"
            />
          </svg>
        </div>

        {/* 404 code */}
        <p className="text-sm font-semibold tracking-widest text-blue-600 dark:text-blue-400 uppercase mb-2">
          404
        </p>

        {/* Heading */}
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-3">
          Page not found
        </h1>

        {/* Description */}
        <p className="text-slate-600 dark:text-slate-400 mb-8">
          The page you&apos;re looking for doesn&apos;t exist or has been moved.
        </p>

        {/* Back to Dashboard button */}
        <Link
          href="/dashboard"
          className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-blue-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-slate-950"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="m15 18-6-6 6-6" />
          </svg>
          Back to Dashboard
        </Link>
      </div>
    </div>
  );
}
