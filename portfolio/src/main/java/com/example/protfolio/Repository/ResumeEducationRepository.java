package com.example.protfolio.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.example.protfolio.Entites.ResumeEducation;
@Repository
public interface ResumeEducationRepository extends MongoRepository<ResumeEducation,String>{

}
