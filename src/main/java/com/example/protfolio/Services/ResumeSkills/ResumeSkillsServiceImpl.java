package com.example.protfolio.Services.ResumeSkills;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.protfolio.Entites.ResumeSkills;
import com.example.protfolio.Repository.ResumeSkillsRepository;
import com.example.protfolio.RequestDTO.ResumeSkillsRequestDTO;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class ResumeSkillsServiceImpl implements ResumeSkillsService {
    @Autowired
    private ResumeSkillsRepository resumeSkillsRepository;

    @Override
    public void CreateResumeSkills(ResumeSkillsRequestDTO resumeSkillsRequestDTO, MultipartFile photo)
            throws IOException {
        ResumeSkills newResumeSkills = new ResumeSkills();
        newResumeSkills.setTitle(resumeSkillsRequestDTO.getTitle());
        if (photo != null && !photo.isEmpty()) {
            newResumeSkills.setNamephotoSkill(photo.getOriginalFilename());
            newResumeSkills.setFilephotoSkill(photo.getBytes());
            newResumeSkills.setTypephotoSkill(photo.getContentType());
        }
        log.info("ResumeSkills added successfully");
        resumeSkillsRepository.save(newResumeSkills);
    }

    @Override
    public void UpdatedResumeSkills(ResumeSkillsRequestDTO resumeSkillsRequestDTO, String idResumeSkills,
            MultipartFile photo) throws IOException {
        ResumeSkills currentResumeSkills = resumeSkillsRepository.findById(idResumeSkills).get();
        if (resumeSkillsRequestDTO.getTitle() != null) {
            currentResumeSkills.setTitle(resumeSkillsRequestDTO.getTitle());
        }
        if (photo != null && !photo.isEmpty()) {
            currentResumeSkills.setNamephotoSkill(photo.getOriginalFilename());
            currentResumeSkills.setFilephotoSkill(photo.getBytes());
            currentResumeSkills.setTypephotoSkill(photo.getContentType());
        }
        log.info("ResumeSkills updated successfully");
        resumeSkillsRepository.save(currentResumeSkills);
    }

    @Override
    public void DeleteResumeSkills(String idResumeSkills) {
        ResumeSkills currentResumeSkills = resumeSkillsRepository.findById(idResumeSkills).get();
        log.info("ResumeSkills deleted successfully");
        resumeSkillsRepository.delete(currentResumeSkills);
    }

    @Override
    public List<ResumeSkills> AllResumeSkills() {
        List<ResumeSkills> resumeSkills = resumeSkillsRepository.findAll();
        log.info("found " + resumeSkills.size() + " resumeSkills");
        return resumeSkills;
    }

}
