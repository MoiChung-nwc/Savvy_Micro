package com.savvy.gradeservice.service;

import com.savvy.gradeservice.api.dto.request.CreateGradeDTO;
import com.savvy.gradeservice.api.dto.request.GradeSearchDTO;
import com.savvy.gradeservice.api.dto.request.UpdateGradeDTO;
import com.savvy.gradeservice.api.dto.response.GradeResponse;
import com.savvy.gradeservice.api.dto.response.StudentGradesResponse;

import java.util.List;
import java.util.UUID;

public interface IGradeService {

    StudentGradesResponse getStudentGrades(UUID studentId, String term, UUID schoolId);
    
    List<GradeResponse> searchGrades(GradeSearchDTO searchRequest);
    
    GradeResponse createGrade(CreateGradeDTO request);
    
    GradeResponse updateGrade(UUID gradeId, UpdateGradeDTO request);
}

