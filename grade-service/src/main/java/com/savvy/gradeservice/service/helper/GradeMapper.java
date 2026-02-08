package com.savvy.gradeservice.service.helper;

import com.savvy.gradeservice.api.dto.response.GradeResponse;
import com.savvy.gradeservice.entity.Grade;
import lombok.experimental.UtilityClass;

@UtilityClass
public class GradeMapper {

    public GradeResponse toResponse(Grade grade) {
        if (grade == null) {
            return null;
        }
        
        return GradeResponse.builder()
                .id(grade.getId())
                .schoolId(grade.getSchoolId())
                .classId(grade.getClassId())
                .studentId(grade.getStudentId())
                .term(grade.getTerm())
                .subject(grade.getSubject())
                .score(grade.getScore())
                .build();
    }
}
