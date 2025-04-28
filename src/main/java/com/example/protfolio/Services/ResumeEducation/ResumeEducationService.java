package com.example.protfolio.Services.ResumeEducation;

import java.util.List;

import com.example.protfolio.Entites.ResumeEducation;
import com.example.protfolio.RequestDTO.ResumeEducationRequestDTO;

public interface ResumeEducationService {
    void CreateResumeEducation(ResumeEducationRequestDTO resumeEducationRequestDTO);

    void UpdatedResumeEducation(ResumeEducationRequestDTO resumeEducationRequestDTO, String idResumeEducation);

    void DeleteResumeEducationt(String idResumeEducation);

    List<ResumeEducation> AllResumeEducation();
}
