package com.savvy.gradeservice.api.dto.request;

import lombok.*;

import java.math.BigDecimal;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateGradeDTO {
    private BigDecimal score;
}