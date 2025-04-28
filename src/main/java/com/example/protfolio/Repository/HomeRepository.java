package com.example.protfolio.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.example.protfolio.Entites.Home;
@Repository
public interface HomeRepository extends MongoRepository<Home,String>{
    Home findByGmail(String gmail); 
}
