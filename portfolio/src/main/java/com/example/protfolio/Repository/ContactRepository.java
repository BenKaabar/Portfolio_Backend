package com.example.protfolio.Repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.example.protfolio.Entites.Contact;
@Repository
public interface ContactRepository extends MongoRepository<Contact,String>{

}
