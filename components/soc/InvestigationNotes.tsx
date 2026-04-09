/**
 * InvestigationNotes - Notes panel for threat investigation
 *
 * Allows SOC analysts to add and view investigation notes.
 */

import type { InvestigationNote } from './InvestigationPanel';

interface InvestigationNotesProps {
  notes: InvestigationNote[];
  noteContent: string;
  setNoteContent: (content: string) => void;
  onAddNote: () => void;
  isSubmitting: boolean;
}

export function InvestigationNotes({
  notes,
  noteContent,
  setNoteContent,
  onAddNote,
  isSubmitting,
}: InvestigationNotesProps) {
  return (
    <div className="space-y-4">
      {/* Add Note */}
      <div>
        <textarea
          value={noteContent}
          onChange={(e) => setNoteContent(e.target.value)}
          placeholder="Add investigation note..."
          className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-blue-500 focus:border-blue-500"
          rows={3}
        />
        <button
          onClick={onAddNote}
          disabled={!noteContent.trim() || isSubmitting}
          className="mt-2 px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isSubmitting ? 'Adding...' : 'Add Note'}
        </button>
      </div>

      {/* Notes List */}
      <div className="space-y-3">
        {notes.length === 0 ? (
          <p className="text-sm text-gray-500 text-center py-4">No investigation notes</p>
        ) : (
          notes.map((note) => (
            <div key={note.id} className="bg-gray-50 rounded p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-gray-900">{note.author}</span>
                <span className="text-xs text-gray-500">
                  {new Date(note.createdAt).toLocaleString()}
                </span>
              </div>
              <p className="text-sm text-gray-600">{note.content}</p>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
