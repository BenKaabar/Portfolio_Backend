package com.example.protfolio.Controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.protfolio.Entites.ResumeExperience;
import com.example.protfolio.RequestDTO.ResumeExperienceRequestDTO;
import com.example.protfolio.Services.ResumeExperience.ResumeExperienceService;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@AllArgsConstructor
@RestController
@CrossOrigin("*")
@RequestMapping(path = "/ResumeExperience")
@Slf4j
public class ResumeExperienceController {
    @Autowired
    private ResumeExperienceService resumeExperienceService;

    @GetMapping("/AllResumeExperience")
    public ResponseEntity<?> AllResumeExperience() {
        try {
            List<ResumeExperience> resumeExperiences = resumeExperienceService.AllResumeExperience();
            return ResponseEntity.ok(resumeExperiences);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PostMapping("/CreateResumeExperience")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> CreateResumeExperience(
            @RequestBody ResumeExperienceRequestDTO resumeExperienceRequestDTO) {
        try {
            resumeExperienceService.CreateResumeExperience(resumeExperienceRequestDTO);
            return ResponseEntity.status(HttpStatus.CREATED).body("ResumeExperience created successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PutMapping("/UpdatedResumeExperience/{idResumeExperience}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> UpdatedResumeExperience(@RequestBody ResumeExperienceRequestDTO resumeExperienceRequestDTO,
            @PathVariable String idResumeExperience) {
        try {
            resumeExperienceService.UpdatedResumeExperience(resumeExperienceRequestDTO, idResumeExperience);
            return ResponseEntity.status(HttpStatus.OK).body("ResumeExperience updated successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @DeleteMapping("/DeleteResumeExperience/{idResumeExperience}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> DeleteResumeExperience(@PathVariable String idResumeExperience) {
        try {
            resumeExperienceService.DeleteResumeExperience(idResumeExperience);
            return ResponseEntity.status(HttpStatus.OK).body("ResumeExperience deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
}
