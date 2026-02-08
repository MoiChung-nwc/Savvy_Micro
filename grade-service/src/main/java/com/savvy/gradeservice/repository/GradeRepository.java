package com.savvy.gradeservice.repository;

import com.savvy.gradeservice.entity.Grade;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface GradeRepository extends JpaRepository<Grade, UUID>, GradeRepositoryCustom {
    
    List<Grade> findByStudentIdAndTerm(UUID studentId, String term);
    
    List<Grade> findByStudentId(UUID studentId);

    List<Grade> findBySchoolIdIn(List<UUID> schoolIds);

    boolean existsByStudentIdAndSubjectAndTerm(UUID studentId, String subject, String term);

}
