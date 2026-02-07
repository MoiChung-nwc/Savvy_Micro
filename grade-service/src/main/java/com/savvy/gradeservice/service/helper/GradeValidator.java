package com.savvy.gradeservice.service.helper;

import com.savvy.common.exception.BusinessException;
import com.savvy.common.exception.ErrorCode;
import lombok.experimental.UtilityClass;
import java.math.BigDecimal;

@UtilityClass
public class GradeValidator {
    private static final BigDecimal MIN_SCORE = BigDecimal.ZERO;
    private static final BigDecimal MAX_SCORE = new BigDecimal("10");

    public void validateScore(BigDecimal score) {
        if (score == null) {
            throw new BusinessException(ErrorCode.INVALID_INPUT, "Score is required");
        }
        
        if (score.compareTo(MIN_SCORE) < 0 || score.compareTo(MAX_SCORE) > 0) {
            throw new BusinessException(
                    ErrorCode.INVALID_INPUT,
                    "Score must be between 0 and 10"
            );
        }
    }

    public void validateSubject(String subject) {
        if (subject == null || subject.trim().isEmpty()) {
            throw new BusinessException(ErrorCode.INVALID_INPUT, "Subject is required");
        }
    }

    public void validateTerm(String term) {
        if (term == null || term.trim().isEmpty()) {
            throw new BusinessException(ErrorCode.INVALID_INPUT, "Term is required");
        }
    }
}
