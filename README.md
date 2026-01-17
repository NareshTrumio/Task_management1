
# 📝 Task Management System (Beginner Project)

This is a **simple Task Management System** built for learning purposes using:

- **Backend:** Spring Boot + MongoDB  
- **Frontend:** React + Tailwind CSS  

The goal of this project is to understand **basic CRUD operations**, frontend–backend communication, and clean beginner-level project structure.

✅ No authentication  
✅ No complex logic  
✅ Easy to modify and extend  

---

## 📌 Features

### Backend
- Create a new task
- List all active (non-deleted) tasks
- Update task **status**
- **Soft delete** a task (using `is_deleted` flag)

### Frontend
- Task creation form
- Task list displayed in a table
- Status update using dropdown
- Soft delete button
- Simple and colorful UI (beginner friendly)

---

## 🗄️ Database Structure (MongoDB)

**Collection:** `tasks`

| Field Name   | Type     | Description |
|-------------|----------|-------------|
| title       | String   | Task title |
| description | String   | Task description |
| status      | String   | Pending / In Progress / Done |
| dueDate     | Date     | Task due date |
| isDeleted   | Boolean  | Soft delete flag |

---




---

## ⚙️ Backend Setup (Spring Boot)

### Prerequisites
- Java 17+
- Maven
- MongoDB running locally

### Steps
```bash
cd backend
mvn spring-boot:run
```
Backend will start at:
http://localhost:8080


---

## 🔗 API Endpoints

### Create Task
- **Method:** POST  
- **URL:** `/tasks`  
- **Description:** Creates a new task

### List Tasks
- **Method:** GET  
- **URL:** `/tasks`  
- **Description:** Returns all active (non-deleted) tasks

### Update Task Status
- **Method:** PATCH  
- **URL:** `/tasks/{id}/status`  
- **Description:** Updates the status of a task

### Soft Delete Task
- **Method:** PATCH  
- **URL:** `/tasks/{id}/delete`  
- **Description:** Soft deletes a task by setting `isDeleted = true`


## 🎨 Frontend Setup (React + Tailwind)

### Prerequisites
- Node.js (v18+ recommended)
- npm

### Steps

```bash
cd frontend
npm install
npm run dev
```
---
Frontend will run at:
http://localhost:5173

