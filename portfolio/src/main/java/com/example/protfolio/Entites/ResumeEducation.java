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
@Document(collection = "ResumeEducation") 
public class ResumeEducation {
    @Id
    private String idResumeEducation;
    private String date;
    private String title;
    private String description;
   
    public void generateIdIfNeeded() {
        if (idResumeEducation == null || idResumeEducation.isEmpty()) {
            this.idResumeEducation = UUID.randomUUID().toString();
        }
    }
}
