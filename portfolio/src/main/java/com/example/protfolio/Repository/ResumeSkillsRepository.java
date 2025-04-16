package com.example.protfolio.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.example.protfolio.Entites.ResumeSkills;
@Repository
public interface ResumeSkillsRepository extends MongoRepository<ResumeSkills,String>{

}
