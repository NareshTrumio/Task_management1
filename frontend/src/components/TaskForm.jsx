
// frontend/src/components/TaskForm.jsx
import { useState } from "react";

const STATUSES = ["Pending", "In Progress", "Completed"];

export default function TaskForm({ onCreate }) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [status, setStatus] = useState("Pending");
  const [dueDate, setDueDate] = useState("");
 
  async function handleSubmit(e) {
    e.preventDefault();
    if (!title.trim()) {
      alert("Please enter a title.");

      return;
    }
  
    await onCreate({
      title,
      description,
      status,
      // Backend expects a date; we’ll send ISO if present, or null
      dueDate: dueDate ? new Date(dueDate) : null,
    });
    // reset
    setTitle("");
    setDescription("");
    setStatus("Pending");
    setDueDate("");
  }

  return (
    <div className="bg-blue-50 border-2 border-blue-300 rounded-md p-4">
      <h2 className="text-xl font-bold text-blue-800 mb-3">Add a Task</h2>

      <form onSubmit={handleSubmit} className="space-y-3">
        <div>
          <label className="block text-sm font-semibold text-blue-900">Title</label>
          <input
            className="mt-1 w-full border-2 border-blue-300 rounded p-2 focus:outline-none focus:ring-2 focus:ring-blue-400 bg-white"
            placeholder="e.g., Buy groceries"
            value={title}
            onChange={(e) =>setTitle(e.target.value) }
          />
           
        </div>

        <div>
          <label className="block text-sm font-semibold text-blue-900">Description</label>
          <textarea
            className="mt-1 w-full border-2 border-blue-300 rounded p-2 bg-white"
            rows={3}
            placeholder="Optional notes..."
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="block text-sm font-semibold text-blue-900">Status</label>
            <select
              className="mt-1 w-full border-2 border-blue-300 rounded p-2 bg-white"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              {STATUSES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            {/* {titleError && <p className="text-red-600 text-sm mt-1">{titleError}</p>} */}
          </div>

          <div>
            <label className="block text-sm font-semibold text-blue-900">Due Date</label>
            <input
              type="date"
              className="mt-1 w-full border-2 border-blue-300 rounded p-2 bg-white"
              value={dueDate}
              onChange={(e) => setDueDate(e.target.value)}
            />
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              className="w-full bg-blue-600 text-white font-semibold py-2 rounded hover:bg-blue-700 active:scale-[.99]"
            >
              Add Task
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
