/**
 * InvestigationActions - Action buttons for threat investigation
 *
 * Provides release, delete, and block sender actions.
 */

import clsx from 'clsx';

interface InvestigationActionsProps {
  onAction?: (action: 'release' | 'delete' | 'block_sender' | 'add_note') => void;
}

export function InvestigationActions({ onAction }: InvestigationActionsProps) {
  return (
    <div className="px-4 py-2 border-b border-gray-200 flex gap-2 flex-wrap">
      <ActionButton
        variant="success"
        onClick={() => onAction?.('release')}
        icon={<CheckIcon className="h-4 w-4" />}
      >
        Release
      </ActionButton>
      <ActionButton
        variant="danger"
        onClick={() => onAction?.('delete')}
        icon={<TrashIcon className="h-4 w-4" />}
      >
        Delete
      </ActionButton>
      <ActionButton
        variant="warning"
        onClick={() => onAction?.('block_sender')}
        icon={<BanIcon className="h-4 w-4" />}
      >
        Block Sender
      </ActionButton>
    </div>
  );
}

function ActionButton({
  children,
  variant,
  onClick,
  icon,
}: {
  children: React.ReactNode;
  variant: 'success' | 'danger' | 'warning';
  onClick?: () => void;
  icon?: React.ReactNode;
}) {
  const variants = {
    success: 'bg-green-100 text-green-700 hover:bg-green-200',
    danger: 'bg-red-100 text-red-700 hover:bg-red-200',
    warning: 'bg-yellow-100 text-yellow-700 hover:bg-yellow-200',
  };

  return (
    <button
      onClick={onClick}
      className={clsx(
        'inline-flex items-center gap-1 px-3 py-1.5 rounded text-sm font-medium transition-colors',
        variants[variant]
      )}
    >
      {icon}
      {children}
    </button>
  );
}

// Icons
function CheckIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  );
}

function TrashIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
    </svg>
  );
}

function BanIcon({ className }: { className?: string }) {
  return (
    <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
    </svg>
  );
}
