package com.example.protfolio.RequestDTO;

import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data

public class WorkRequestDTO {
    private String projectType;
    private String title;
    private String shortDescription;
    @Size(max = 255, message = "Long description must not exceed 255 characters.")
    private String longDescription;
    private String mainTechnology;
    private String allTechnology;
    private String github;
    private String video;
    private String namephotoWork;
    private String typephotoWork;
}
