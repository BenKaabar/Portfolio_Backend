package com.example.protfolio.Services.ResumeExperience;

import java.util.List;

import com.example.protfolio.Entites.ResumeExperience;
import com.example.protfolio.RequestDTO.ResumeExperienceRequestDTO;

public interface ResumeExperienceService {
    void CreateResumeExperience(ResumeExperienceRequestDTO resumeExperienceRequestDTO);

    void UpdatedResumeExperience(ResumeExperienceRequestDTO resumeExperienceRequestDTO, String idResumeExperience);

    void DeleteResumeExperience(String idResumeExperience);

    List<ResumeExperience> AllResumeExperience();
}
