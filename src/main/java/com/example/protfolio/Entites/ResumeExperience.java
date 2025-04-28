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
@Document(collection = "ResumeExperience") 
public class ResumeExperience {
    @Id
    private String idResumeExperience;
    private String date;
    private String title;
    private String description;

    public void generateIdIfNeeded() {
        if (idResumeExperience == null || idResumeExperience.isEmpty()) {
            this.idResumeExperience = UUID.randomUUID().toString();
        }
    }
}
