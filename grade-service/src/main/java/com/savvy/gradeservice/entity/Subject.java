package com.savvy.gradeservice.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Entity
@Table(name = "subjects")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Subject {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    @Column(nullable = false, length = 50, unique = true)
    private String code;
    
    @Column(nullable = false, length = 255)
    private String name;
    

    public Subject(String code, String name) {
        this.code = code;
        this.name = name;
    }
}
