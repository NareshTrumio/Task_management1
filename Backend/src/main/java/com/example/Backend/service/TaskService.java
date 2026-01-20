
package com.example.Backend.service;

import com.example.Backend.model.Task;
import com.example.Backend.repository.TaskRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class TaskService {

    private final TaskRepository repo;

    public TaskService(TaskRepository repo) {
        this.repo = repo;
    }

    public Task create(Task t) {
        if (t.getStatus() == null || t.getStatus().isBlank()) {
            t.setStatus("Pending");
        }
        t.setDeleted(false);
        return repo.save(t);
    }

    public List<Task> listActive() {

        return repo.findByIsDeletedFalseOrderByDueDateAsc();
    }

    public Optional<Task> updateStatus(String id, String status) {
        return repo.findById(id).map(task -> {
            task.setStatus(status);
            return repo.save(task);
        });
    }

    public boolean softDelete(String id) {
        return repo.findById(id).map(task -> {
            task.setDeleted(true);
            repo.save(task);
            return true;
        }).orElse(false);
    }
}
