package com.example.protfolio.RequestDTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class HomeRequestDTO {
    private String speciality;
    private String name;
    private String description;
    private String address;
    private String password;
    private String gitHub;
    private String gmail;
    private String whatsApp;
    private String linkedIn;
    private String language;
    private String nationnality;
    private String nameCvFile;
    private String typeCvFile;
    private String namephoto;
    private String typephoto;
}
