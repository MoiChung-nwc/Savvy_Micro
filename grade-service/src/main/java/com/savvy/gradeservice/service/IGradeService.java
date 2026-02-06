package com.savvy.gradeservice.service;

import com.savvy.gradeservice.api.dto.request.CreateGradeRequest;
import com.savvy.gradeservice.api.dto.request.UpdateGradeRequest;
import com.savvy.gradeservice.api.dto.response.GradeResponse;
import com.savvy.gradeservice.api.dto.response.StudentGradesResponse;

import java.util.List;
import java.util.UUID;

public interface IGradeService {

    StudentGradesResponse getStudentGrades(UUID studentId, String term, UUID schoolId);

    List<GradeResponse> getAllGrades(); // For ADMIN only

    GradeResponse createGrade(CreateGradeRequest request);

    GradeResponse updateGrade(UUID gradeId, UpdateGradeRequest request);
}
