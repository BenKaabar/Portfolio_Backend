package com.example.protfolio.Services.ResumeSkills;

import java.io.IOException;
import java.util.List;

import org.springframework.web.multipart.MultipartFile;

import com.example.protfolio.Entites.ResumeSkills;
import com.example.protfolio.RequestDTO.ResumeSkillsRequestDTO;

public interface ResumeSkillsService {
    void CreateResumeSkills(ResumeSkillsRequestDTO resumeSkillsRequestDTO, MultipartFile photo) throws IOException;

    void UpdatedResumeSkills(ResumeSkillsRequestDTO resumeSkillsRequestDTO, String idResumeSkills, MultipartFile photo) throws IOException;

    void DeleteResumeSkills(String idResumeSkills);

    List<ResumeSkills> AllResumeSkills();
}
