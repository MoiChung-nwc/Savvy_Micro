package cd.studentservice.entity;

import cd.studentservice.enumerate.StudentStatus;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

@Entity
@Table(name = "students")
@FieldDefaults(level = AccessLevel.PRIVATE)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Student {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    UUID id;

    @Column(unique = true,nullable = false)
    String code;

    String fullName;
    LocalDate dob;
    Boolean gender;
    @Enumerated(EnumType.STRING)
    StudentStatus status;
    @CreationTimestamp
    Instant createdAt;

    @ManyToOne
    @JoinColumn(name = "class_id")
    Class clazz;
}
