package cd.studentservice.service.impl;

import cd.studentservice.dto.response.ClassResponse;
import cd.studentservice.entity.Class;
import cd.studentservice.mapper.ClassMapper;
import cd.studentservice.repository.ClassRepository;
import cd.studentservice.service.ClassService;
import com.savvy.common.dto.PageResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ClassServiceImpl implements ClassService {
    private final ClassRepository classRepository;
    private final ClassMapper classMapper;

    @Override
    public Class findById(UUID id) {
        return classRepository.findById(id).orElseThrow(() -> new RuntimeException("Cannot find class with id: " + id));
    }

    @Override
    public List<ClassResponse> findBySchoolId(UUID schoolId) {
        return classMapper.toClassResponses(classRepository.findAllBySchoolId(schoolId));
    }

    @Override
    public Class getReferenceById(UUID id) {
        return classRepository.getReferenceById(id);
    }
}
