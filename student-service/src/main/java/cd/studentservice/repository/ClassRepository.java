package cd.studentservice.repository;

import cd.studentservice.entity.Class;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface ClassRepository extends JpaRepository<Class, UUID> {
    List<Class>findAllBySchoolId(UUID schoolId);
}