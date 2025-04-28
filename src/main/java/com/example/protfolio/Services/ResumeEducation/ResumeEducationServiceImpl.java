package com.example.protfolio.Services.ResumeEducation;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.protfolio.Entites.ResumeEducation;
import com.example.protfolio.Repository.ResumeEducationRepository;
import com.example.protfolio.RequestDTO.ResumeEducationRequestDTO;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class ResumeEducationServiceImpl implements ResumeEducationService {
    @Autowired
    private ResumeEducationRepository resumeEducationRepository;

    @Override
    public void CreateResumeEducation(ResumeEducationRequestDTO resumeEducationRequestDTO) {
        ResumeEducation newResumeEducation = new ResumeEducation();
        newResumeEducation.setDate(resumeEducationRequestDTO.getDate());
        newResumeEducation.setTitle(resumeEducationRequestDTO.getTitle());
        newResumeEducation.setDescription(resumeEducationRequestDTO.getDescription());
        log.info("ResumeEducation added successfully");
        resumeEducationRepository.save(newResumeEducation);
    }

    @Override
    public void UpdatedResumeEducation(ResumeEducationRequestDTO resumeEducationRequestDTO, String idResumeEducation) {
        ResumeEducation currentResumeEducation = resumeEducationRepository.findById(idResumeEducation).get();
        if(resumeEducationRequestDTO.getDate() != null){
            currentResumeEducation.setDate(resumeEducationRequestDTO.getDate());
        }
        if(resumeEducationRequestDTO.getTitle() != null){
            currentResumeEducation.setTitle(resumeEducationRequestDTO.getTitle());
        }
        if(resumeEducationRequestDTO.getDescription() != null){
            currentResumeEducation.setDescription(resumeEducationRequestDTO.getDescription());
        }
        log.info("ResumeEducation updated successfully");
        resumeEducationRepository.save(currentResumeEducation);
    }

    @Override
    public void DeleteResumeEducationt(String idResumeEducation) {
        ResumeEducation currentResumeEducation = resumeEducationRepository.findById(idResumeEducation).get();
        log.info("ResumeEducation deleted successfully");
        resumeEducationRepository.delete(currentResumeEducation);
    }

    @Override
    public List<ResumeEducation> AllResumeEducation() {
        List<ResumeEducation> ResumeEducation = resumeEducationRepository.findAll();
        log.info("found " + ResumeEducation.size() + " ResumeEducation");
        return ResumeEducation;
    }

}
