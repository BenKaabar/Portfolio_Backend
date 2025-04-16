package com.example.protfolio.Services.ResumeExperience;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.protfolio.Entites.ResumeExperience;
import com.example.protfolio.Repository.ResumeExperienceRepository;
import com.example.protfolio.RequestDTO.ResumeExperienceRequestDTO;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class ResumeExperienceServiceImpl implements ResumeExperienceService {
    @Autowired
    private ResumeExperienceRepository resumeExperienceRepository;

    @Override
    public void CreateResumeExperience(ResumeExperienceRequestDTO resumeExperienceRequestDTO) {
        ResumeExperience newResumeExperience = new ResumeExperience();
        newResumeExperience.setDate(resumeExperienceRequestDTO.getDate());
        newResumeExperience.setTitle(resumeExperienceRequestDTO.getTitle());
        newResumeExperience.setDescription(resumeExperienceRequestDTO.getDescription());
        log.info("ResumeExperience added successfully");
        resumeExperienceRepository.save(newResumeExperience);
    }

    @Override
    public void UpdatedResumeExperience(ResumeExperienceRequestDTO resumeExperienceRequestDTO,
            String idResumeExperience) {
        ResumeExperience currentResumeExperience = resumeExperienceRepository.findById(idResumeExperience).get();
        if (resumeExperienceRequestDTO.getDate() != null) {
            currentResumeExperience.setDate(resumeExperienceRequestDTO.getDate());
        }
        if (resumeExperienceRequestDTO.getTitle() != null) {
            currentResumeExperience.setTitle(resumeExperienceRequestDTO.getTitle());
        }
        if (resumeExperienceRequestDTO.getDescription() != null) {
            currentResumeExperience.setDescription(resumeExperienceRequestDTO.getDescription());
        }
        log.info("resumeExperience updated successfully");
        resumeExperienceRepository.save(currentResumeExperience);
    }

    @Override
    public void DeleteResumeExperience(String idResumeExperience) {
        ResumeExperience currentResumeExperience = resumeExperienceRepository.findById(idResumeExperience).get();
        log.info("ResumeExperience deleted successfully");
        resumeExperienceRepository.delete(currentResumeExperience);
    }
    
    @Override
    public List<ResumeExperience> AllResumeExperience() {
        List<ResumeExperience> resumeExperiences = resumeExperienceRepository.findAll();
        log.info("found " + resumeExperiences.size() + " resumeExperiences");
        return resumeExperiences;
    }

}
