package cd.studentservice.service;

import cd.studentservice.dto.response.ClassResponse;
import cd.studentservice.entity.Class;
import com.savvy.common.dto.PageResponse;
import org.springframework.data.domain.Page;

import java.util.List;
import java.util.UUID;

public interface ClassService {
    Class findById(UUID id);
    List<ClassResponse> findBySchoolId(UUID schoolId);
    Class getReferenceById(UUID id);
}
