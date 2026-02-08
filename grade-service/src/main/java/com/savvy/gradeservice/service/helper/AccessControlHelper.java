package com.savvy.gradeservice.service.helper;

import com.savvy.common.exception.BusinessException;
import com.savvy.common.exception.ErrorCode;
import com.savvy.gradeservice.config.UserContext;
import lombok.experimental.UtilityClass;

import java.util.List;
import java.util.UUID;

@UtilityClass
public class AccessControlHelper {

    public List<UUID> getAccessibleSchoolIds(UserContext context) {
        if (context.isAdmin()) {
            return null; 
        }
        
        if (context.isManager()) {
            List<UUID> schoolIds = context.getAccessibleSchoolIds();
            if (schoolIds == null || schoolIds.isEmpty()) {
                throw new BusinessException(
                        ErrorCode.FORBIDDEN,
                        "Manager has no accessible schools in dataScope"
                );
            }
            return schoolIds;
        }
        
        throw new BusinessException(
                ErrorCode.FORBIDDEN,
                "Only ADMIN and MANAGER can access grades"
        );
    }

    
    public void verifySchoolAccess(UserContext context, UUID schoolId) {
        if (schoolId == null) {
            throw new BusinessException(ErrorCode.INVALID_INPUT, "SchoolId is required");
        }
        
        if (context.isAdmin()) {
            return; // ADMIN has full access
        }
        
        if (context.isManager()) {
            if (!context.hasSchoolAccess(schoolId)) {
                throw new BusinessException(
                        ErrorCode.FORBIDDEN,
                        "SchoolId not in your scope"
                );
            }
            return;
        }
        
        throw new BusinessException(
                ErrorCode.FORBIDDEN,
                "Insufficient permission to access this school"
        );
    }

   
    public void verifyStudentAccess(UserContext context, UUID requestedStudentId) {
        if (!context.isStudent()) {
            return;
        }
        
        if (!requestedStudentId.equals(context.getUserId())) {
            throw new BusinessException(
                    ErrorCode.FORBIDDEN,
                    "Student can only access their own grades"
            );
        }
    }

   
    public void verifyGradeReadPermission(UserContext context) {
        if (!context.canReadGrades()) {
            throw new BusinessException(
                    ErrorCode.FORBIDDEN,
                    "Permission denied: GRADE_READ required"
            );
        }
    }
}
