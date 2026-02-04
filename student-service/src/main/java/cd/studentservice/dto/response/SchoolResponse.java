package cd.studentservice.dto.response;

import cd.studentservice.enumerate.SchoolStatus;

import java.time.Instant;
import java.util.UUID;

public record SchoolResponse(
        UUID id,
        String code,
        String name,
        String address,
        SchoolStatus status,
        Instant createdAt) {
}
