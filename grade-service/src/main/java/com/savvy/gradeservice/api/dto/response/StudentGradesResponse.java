package com.savvy.gradeservice.api.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StudentGradesResponse {
    private UUID studentId;
    private String term;
    private List<GradeItemResponse> items;
}
