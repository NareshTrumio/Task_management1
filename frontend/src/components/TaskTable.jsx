
import { useEffect, useState } from "react";
import { listTasks, updateStatus, softDelete } from "../api";

const STATUSES = ["Pending", "In Progress", "Completed","overdue"];

export default function TaskTable({ refreshKey }) {
  const [tasks, setTasks] = useState([]);

  async function load() {
    const data = await listTasks();
    setTasks(data);
  }

  useEffect(() => { 
    load();
 }, [refreshKey]);

  const onStatusChange = async (id, status) => {
    await updateStatus(id, status);
    load();
  };

  const onDelete = async (id) => {
    if (confirm("Soft delete this task?")) {
      await softDelete(id);
      load();
    }
  };

  return (
    <div className="bg-white rounded border">
      <table className="w-full text-left">
        <thead className="bg-green-100 border-b">
          <tr>
            <th className="p-3">Title</th>
            <th className="p-3">Description</th>
            <th className="p-3">Status</th>
            <th className="p-3">Due Date</th>
            <th className="p-3">Actions</th>
          </tr>
        </thead>
        <tbody>
          {tasks.length === 0 && (
            <tr><td colSpan="5" className="p-4 text-center text-gray-500">No tasks</td></tr>
          )}
          {tasks.map(t => (
            <tr key={t.id} className="border-t">
              <td className="p-3">{t.title}</td>
              <td className="p-3 text-gray-600">{t.description}</td>
              <td className="p-3">
                <select
                  className="border rounded p-1"
                  value={t.status}
                  onChange={(e) => onStatusChange(t.id, e.target.value)}
                >
                  {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </td>
              <td className="p-3">
                {t.dueDate ? new Date(t.dueDate).toLocaleDateString() : "-"}
                {t.dueDate && new Date(t.dueDate) < new Date() && t.status !== "Completed" && (
                  <span className="ml-2 text-red-600 font-semibold">(Overdue)</span>
                )}
              </td>
              <td className="p-3">
                <button onClick={() => onDelete(t.id)} className="text-neutral-50 bg-red-500 hover:bg-red-600 hover:border-red-700 rounded px-2 py-1">
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
