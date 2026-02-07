package com.savvy.gradeservice.repository;

import com.querydsl.core.BooleanBuilder;
import com.querydsl.jpa.impl.JPAQueryFactory;
import com.savvy.gradeservice.api.dto.request.GradeSearchDTO;
import com.savvy.gradeservice.entity.Grade;
import com.savvy.gradeservice.entity.QGrade;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
//  DIP
public class GradeRepositoryImpl implements GradeRepositoryCustom {

    private final EntityManager entityManager;

    @Override
    public List<Grade> searchGradesWithAccessControl(GradeSearchDTO searchRequest, List<UUID> accessibleSchoolIds) {
        JPAQueryFactory queryFactory = new JPAQueryFactory(entityManager);
        QGrade grade = QGrade.grade;// là class được QueryDSL generate tự động từ entity Grade
        BooleanBuilder builder = new BooleanBuilder(); //  điều kiện truy vấn động
        if (accessibleSchoolIds != null && !accessibleSchoolIds.isEmpty()) {
            builder.and(grade.schoolId.in(accessibleSchoolIds));
        }

        if (searchRequest != null) {
            if (searchRequest.getSchoolId() != null) {
                builder.and(grade.schoolId.eq(searchRequest.getSchoolId()));
            }
            
            if (searchRequest.getClassId() != null) {
                builder.and(grade.classId.eq(searchRequest.getClassId()));
            }
            
            if (searchRequest.getStudentId() != null) {
                builder.and(grade.studentId.eq(searchRequest.getStudentId()));
            }
            
            if (StringUtils.hasText(searchRequest.getSubject())) {
                builder.and(grade.subject.containsIgnoreCase(searchRequest.getSubject()));  // tìm kiếm gần đúng, không phân biệt hoa thường tương tự like %subject%
            }
            
            if (StringUtils.hasText(searchRequest.getTerm())) {
                builder.and(grade.term.eq(searchRequest.getTerm())); // chỉ lấy học kỳ đúng
            }
            
            if (searchRequest.getMinScore() != null) {
                builder.and(grade.score.goe(searchRequest.getMinScore())); // lây điểm lớn hơn hoặc bằng
            }
            
            if (searchRequest.getMaxScore() != null) {
                builder.and(grade.score.loe(searchRequest.getMaxScore()));// lấy điểm nhỏ hơn hoặc bằng
            }
        }
        
        return queryFactory
                .selectFrom(grade)  // chọn từ bảng grade ( entity Grade)
                .where(builder) // áp dụng điều kiện truy 
                .orderBy(grade.createdAt.desc()) // sắp xếp theo ngày tạo giảm dần
                .fetch(); // thực hiện truy vấn và trả về kết quả dưới dạng danh sách Grade
    }
}
