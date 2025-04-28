package com.example.protfolio.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.example.protfolio.Entites.ResumeExperience;
@Repository
public interface ResumeExperienceRepository extends MongoRepository<ResumeExperience,String>{

}
