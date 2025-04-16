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
@Document(collection = "resumeSkills") 
public class ResumeSkills {
    @Id
    private String idResumeSkills;
    private String title;
    private String namephotoSkill;
    private String typephotoSkill;
    private byte[] filephotoSkill;

    public void generateIdIfNeeded() {
        if (idResumeSkills == null || idResumeSkills.isEmpty()) {
            this.idResumeSkills = UUID.randomUUID().toString();
        }
    }
}
