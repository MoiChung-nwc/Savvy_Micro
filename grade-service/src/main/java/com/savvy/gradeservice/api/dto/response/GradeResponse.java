package com.savvy.gradeservice.api.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GradeResponse {
    private UUID id;
    private UUID schoolId;
    private UUID classId;
    private UUID studentId;
    private String term;
    private String subject;
    private BigDecimal score;
}
