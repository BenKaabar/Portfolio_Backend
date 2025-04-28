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
@Document(collection = "Work") 
public class Work {
    @Id
    private String idWork;
    private String projectType;
    private String title;
    private String shortDescription;
    private String longDescription;
    private String mainTechnology;
    private String allTechnology;
    private String github;
    private String video;
    private String namephotoWork;
    private String typephotoWork;
    private byte[] filephotoWork;

    public void generateIdIfNeeded() {
        if (idWork == null || idWork.isEmpty()) {
            this.idWork = UUID.randomUUID().toString();
        }
    }
}
