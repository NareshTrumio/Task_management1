
import { useState } from "react";
import TaskForm from "./components/TaskForm";
import TaskTable from "./components/TaskTable";
import { createTask } from "./api";
import "./index.css";

export default function App() {
  const [refreshKey, setRefreshKey] = useState(0);

  const handleCreate = async (task) => {
    await createTask(task);
    setRefreshKey(k => k + 1);
  };

  return (
    <div className="min-h-screen bg-orange-100">
      <header className="bg-white border-b">
        <div className="max-w-4xl mx-auto p-4">
          <h1 className="text-2xl font-bold">Task Manager</h1>
          <p className="text-gray-600">Create, view, update status, and soft delete tasks</p>
        </div>
      </header>

      <main className="max-w-4xl mx-auto p-4 space-y-4">
        <TaskForm onCreate={handleCreate} />
       
        <TaskTable refreshKey={refreshKey} />
      </main>
    </div>
  );
}
