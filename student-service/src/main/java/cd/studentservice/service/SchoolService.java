package cd.studentservice.service;

import cd.studentservice.dto.request.CreateSchoolRequest;
import cd.studentservice.dto.request.CreateStudentRequest;
import cd.studentservice.dto.request.UpdateSchoolRequest;
import cd.studentservice.dto.response.SchoolResponse;
import cd.studentservice.entity.School;
import com.savvy.common.dto.PageResponse;

import java.util.UUID;

public interface SchoolService {
    School findById(UUID id);
    School getReferenceById(UUID id);
    PageResponse<SchoolResponse>getPages(int size,int page);
    School save(CreateSchoolRequest request);
    School update(UUID id, UpdateSchoolRequest request);
}
