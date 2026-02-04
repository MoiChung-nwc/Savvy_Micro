package cd.studentservice.dto.response;

import cd.studentservice.enumerate.StudentStatus;

import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

public record StudentResponse(
        UUID id,
        String code,
        String fullName,
        LocalDate dob,
        Boolean gender,
        StudentStatus status,
        Instant createdAt,
        ClassResponse clazz) {
}
