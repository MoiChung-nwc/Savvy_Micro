package com.savvy.gradeservice.entity;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;


/**
 * QGrade is a Querydsl query type for Grade
 */
@Generated("com.querydsl.codegen.DefaultEntitySerializer")
public class QGrade extends EntityPathBase<Grade> {

    private static final long serialVersionUID = -1958915348L;

    public static final QGrade grade = new QGrade("grade");

    public final ComparablePath<java.util.UUID> classId = createComparable("classId", java.util.UUID.class);

    public final DateTimePath<java.time.Instant> createdAt = createDateTime("createdAt", java.time.Instant.class);

    public final ComparablePath<java.util.UUID> createdBy = createComparable("createdBy", java.util.UUID.class);

    public final ComparablePath<java.util.UUID> id = createComparable("id", java.util.UUID.class);

    public final ComparablePath<java.util.UUID> schoolId = createComparable("schoolId", java.util.UUID.class);

    public final NumberPath<java.math.BigDecimal> score = createNumber("score", java.math.BigDecimal.class);

    public final ComparablePath<java.util.UUID> studentId = createComparable("studentId", java.util.UUID.class);

    public final StringPath subject = createString("subject");

    public final StringPath term = createString("term");

    public final DateTimePath<java.time.Instant> updatedAt = createDateTime("updatedAt", java.time.Instant.class);

    public QGrade(String variable) {
        super(Grade.class, forVariable(variable));
    }

    public QGrade(Path<? extends Grade> path) {
        super(path.getType(), path.getMetadata());
    }

    public QGrade(PathMetadata metadata) {
        super(Grade.class, metadata);
    }

}

