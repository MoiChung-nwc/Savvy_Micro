package cd.studentservice.dto.request;

import cd.studentservice.enumerate.StudentStatus;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;
import java.util.UUID;

@Getter
@Setter
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UpdateStudentRequest {
    String code;
    String fullName;
    LocalDate dob;
    Boolean gender;
    StudentStatus status;
    UUID schoolId;
    UUID classId;
}
