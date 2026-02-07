package com.savvy.gradeservice.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "grades", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"student_id", "subject_id", "term"})
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Grade {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    protected UUID id;

    @Column(name = "school_id", nullable = false)
    private UUID schoolId;
    
    @Column(name = "class_id", nullable = false)
    private UUID classId;
    
    @Column(name = "student_id", nullable = false)
    private UUID studentId;
    @Column(name = "subject_id", nullable = false,length = 30)
    private String subject;
    
    @Column(nullable = false, length = 20)
    private String term;
    
    @Column(nullable = false, precision = 4, scale = 2)
    private BigDecimal score;
    
    @Column(name = "created_by")
    private UUID createdBy;
    
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
    
    @Column(name = "updated_at")
    private Instant updatedAt;
    
    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        updatedAt = Instant.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }
}
