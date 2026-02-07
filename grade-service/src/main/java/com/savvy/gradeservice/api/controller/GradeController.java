package com.savvy.gradeservice.api.controller;

import com.savvy.common.dto.BaseResponse;
import com.savvy.gradeservice.api.dto.request.CreateGradeDTO;
import com.savvy.gradeservice.api.dto.request.GradeSearchDTO;
import com.savvy.gradeservice.api.dto.request.UpdateGradeDTO;
import com.savvy.gradeservice.api.dto.response.GradeResponse;
import com.savvy.gradeservice.api.dto.response.StudentGradesResponse;
import com.savvy.gradeservice.service.IGradeService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/grades")
@RequiredArgsConstructor
public class GradeController {
    
    private final IGradeService gradeService;

    @GetMapping
    public BaseResponse<List<GradeResponse>> searchGrades(
            @RequestParam(required = false) UUID schoolId,
            @RequestParam(required = false) UUID classId,
            @RequestParam(required = false) UUID studentId,
            @RequestParam(required = false) String subject,
            @RequestParam(required = false) String term,
            @RequestParam(required = false) java.math.BigDecimal minScore,
            @RequestParam(required = false) java.math.BigDecimal maxScore
    ) {
        GradeSearchDTO searchRequest = GradeSearchDTO.builder()
                .schoolId(schoolId)
                .classId(classId)
                .studentId(studentId)
                .subject(subject)
                .term(term)
                .minScore(minScore)
                .maxScore(maxScore)
                .build();
        
        List<GradeResponse> response = gradeService.searchGrades(searchRequest);
        return BaseResponse.success(response);
    }


    @GetMapping("/students/{studentId}")
    public BaseResponse<StudentGradesResponse> getStudentGrades(
            @PathVariable UUID studentId,
            @RequestParam String term,
            @RequestParam UUID schoolId
    ) {
        StudentGradesResponse response = gradeService.getStudentGrades(studentId, term, schoolId);
        return BaseResponse.success(response);
    }

    @PostMapping
    public BaseResponse<GradeResponse> createGrade(
            @Valid @RequestBody CreateGradeDTO request
    ) {
        GradeResponse response = gradeService.createGrade(request);
        return BaseResponse.created(response, "Grade created successfully");
    }


    @PutMapping("/{gradeId}")
    public BaseResponse<GradeResponse> updateGrade(
            @PathVariable UUID gradeId,
            @Valid @RequestBody UpdateGradeDTO request
    ) {
        GradeResponse response = gradeService.updateGrade(gradeId, request);
        return BaseResponse.success(response, "Grade updated successfully");
    }
}
