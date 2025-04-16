package com.example.protfolio.Entites;

import java.util.UUID;

import org.springframework.data.mongodb.core.mapping.Document;

import org.springframework.data.annotation.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Document(collection = "contacts") 
public class Contact {
    @Id
    private String idContact;
    private String firstName;
    private String lastName;
    private String phone;
    private String email;
    private String message;
    private String service;

    public void generateIdIfNeeded() {
        if (idContact == null || idContact.isEmpty()) {
            this.idContact = UUID.randomUUID().toString();
        }
    }
}
