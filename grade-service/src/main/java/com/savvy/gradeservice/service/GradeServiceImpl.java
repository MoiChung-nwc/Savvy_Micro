package com.savvy.gradeservice.service;

import com.savvy.common.exception.BusinessException;
import com.savvy.common.exception.ErrorCode;
import com.savvy.gradeservice.api.dto.request.CreateGradeDTO;
import com.savvy.gradeservice.api.dto.request.GradeSearchDTO;
import com.savvy.gradeservice.api.dto.request.UpdateGradeDTO;
import com.savvy.gradeservice.api.dto.response.GradeItemResponse;
import com.savvy.gradeservice.api.dto.response.GradeResponse;
import com.savvy.gradeservice.api.dto.response.StudentGradesResponse;
import com.savvy.gradeservice.config.UserContext;
import com.savvy.gradeservice.entity.Grade;
import com.savvy.gradeservice.repository.GradeRepository;
import com.savvy.gradeservice.service.helper.AccessControlHelper;
import com.savvy.gradeservice.service.helper.GradeMapper;
import com.savvy.gradeservice.service.helper.GradeValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class GradeServiceImpl implements IGradeService {

    private final GradeRepository gradeRepository;

    @Override
    @Transactional(readOnly = true)
    public StudentGradesResponse getStudentGrades(UUID studentId, String term, UUID schoolId) {
        UserContext context = UserContext.get();

        AccessControlHelper.verifySchoolAccess(context, schoolId);
        GradeValidator.validateTerm(term);

        if (context.isStudent()) {
            AccessControlHelper.verifyStudentAccess(context, studentId);
        }
        if (context.isManager()) {
            List<Grade> existingGrades = gradeRepository.findByStudentId(studentId);
            if (!existingGrades.isEmpty()) {
                UUID actualSchoolId = existingGrades.get(0).getSchoolId();
                if (!schoolId.equals(actualSchoolId)) {
                    throw new BusinessException(
                            ErrorCode.FORBIDDEN,
                            "SchoolId does not match student's school"
                    );
                }
            }
        }

        List<Grade> grades = gradeRepository.findByStudentIdAndTerm(studentId, term)
                .stream()
                .filter(grade -> schoolId.equals(grade.getSchoolId()))
                .toList();

        List<GradeItemResponse> items = grades.stream()
                .map(grade -> GradeItemResponse.builder()
                        .subject(grade.getSubject())
                        .score(grade.getScore())
                        .build())
                .toList();

        return StudentGradesResponse.builder()
                .studentId(studentId)
                .term(term)
                .items(items)
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public List<GradeResponse> searchGrades(GradeSearchDTO searchRequest) {
        UserContext context = UserContext.get();

        AccessControlHelper.verifyGradeReadPermission(context);

        List<UUID> accessibleSchoolIds = AccessControlHelper.getAccessibleSchoolIds(context);

        List<Grade> grades = gradeRepository.searchGradesWithAccessControl(searchRequest, accessibleSchoolIds);

        return grades.stream()
                .map(GradeMapper::toResponse)
                .toList();
    }

    @Override
    public GradeResponse createGrade(CreateGradeDTO request) {
        UserContext context = UserContext.get();

        AccessControlHelper.verifySchoolAccess(context, request.getSchoolId());
        GradeValidator.validateScore(request.getScore());
        GradeValidator.validateSubject(request.getSubject());
        GradeValidator.validateTerm(request.getTerm());
        if (gradeRepository.existsByStudentIdAndSubjectAndTerm(
                request.getStudentId(),
                request.getSubject(),
                request.getTerm())) {
            throw new BusinessException(
                    ErrorCode.GRADE_ALREADY_EXISTS,
                    "Grade already exists for this student, subject and term"
            );
        }

     
        Grade grade = Grade.builder()
                .schoolId(request.getSchoolId())
                .classId(request.getClassId())
                .studentId(request.getStudentId())
                .term(request.getTerm())
                .subject(request.getSubject())
                .score(request.getScore())
                .createdBy(context.getUserId())
                .build();

        Grade savedGrade = gradeRepository.save(grade);

        return GradeMapper.toResponse(savedGrade);
    }

    @Override

    public GradeResponse updateGrade(UUID gradeId, UpdateGradeDTO request) {
        UserContext context = UserContext.get();

        // Find existing grade
        Grade grade = gradeRepository.findById(gradeId)
                .orElseThrow(() -> new BusinessException(
                        ErrorCode.INVALID_INPUT,
                        "Grade not found: " + gradeId
                ));

        // Verify school access for MANAGER
        AccessControlHelper.verifySchoolAccess(context, grade.getSchoolId());

        // Validate score
        GradeValidator.validateScore(request.getScore());

        // Update the score
        grade.setScore(request.getScore());
        Grade updatedGrade = gradeRepository.save(grade);

        log.info("Updated grade {} by user {}", gradeId, context.getUserId());

        return GradeMapper.toResponse(updatedGrade);
    }
}
