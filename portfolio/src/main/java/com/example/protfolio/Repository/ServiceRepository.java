package com.example.protfolio.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.example.protfolio.Entites.Services;
@Repository
public interface ServiceRepository extends MongoRepository<Services,String>{

}
