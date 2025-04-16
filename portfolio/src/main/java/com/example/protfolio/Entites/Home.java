package com.example.protfolio.Entites;

import java.util.UUID;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Document(collection = "Home") 
public class Home {
    @Id
    private String idUser;
    private String speciality;
    private String name;
    private String password;
    private String description;
    private String address;
    private String gitHub;
    private String gmail;
    private String whatsApp;
    private String linkedIn;
    private String language;
    private String nationnality;
    private String nameCvFile;
    private String typeCvFile;
    private byte[] cvFile;
    private String namephoto;
    private String typephoto;
    private byte[] filephoto;

    public void generateIdIfNeeded() {
        if (idUser == null || idUser.isEmpty()) {
            this.idUser = UUID.randomUUID().toString();
        }
    }
}
