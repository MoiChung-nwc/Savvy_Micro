package cd.studentservice.dto.response;

import cd.studentservice.enumerate.ClassStatus;
import cd.studentservice.mapper.SchoolMapper;
import org.mapstruct.Mapper;

import java.time.Instant;
import java.util.UUID;

public record ClassResponse(
        UUID id,
        String code,
        String name,
        Integer grade,
        ClassStatus status,
        Instant createdAt,
        SchoolResponse school) {
}
