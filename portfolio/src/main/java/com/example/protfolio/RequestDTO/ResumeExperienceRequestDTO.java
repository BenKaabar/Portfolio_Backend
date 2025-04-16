package com.example.protfolio.RequestDTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class ResumeExperienceRequestDTO {
    private String title;
    private String date;
    private String description;
}
