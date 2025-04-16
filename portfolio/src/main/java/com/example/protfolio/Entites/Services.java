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
@Document(collection = "Service") 
public class Services {
    @Id
    private String idService;
    private String title;
    private String technology;

    public void generateIdIfNeeded() {
        if (idService == null || idService.isEmpty()) {
            this.idService = UUID.randomUUID().toString();
        }
    }
}
