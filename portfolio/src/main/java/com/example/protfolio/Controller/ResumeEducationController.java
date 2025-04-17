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

import com.example.protfolio.Entites.ResumeEducation;
import com.example.protfolio.RequestDTO.ResumeEducationRequestDTO;
import com.example.protfolio.Services.ResumeEducation.ResumeEducationService;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@AllArgsConstructor
@RestController
@CrossOrigin(origins = "https://astonishing-sherbet-feb009.netlify.app")
@RequestMapping(path = "/ResumeEducation")
@Slf4j
public class ResumeEducationController {
    @Autowired
    private ResumeEducationService resumeEducationService;

    @GetMapping("/AllResumeEducation")
    public ResponseEntity<?> AllResumeEducation() {
        try {
            List<ResumeEducation> ResumeEducations = resumeEducationService.AllResumeEducation();
            return ResponseEntity.ok(ResumeEducations);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PostMapping("/CreateResumeEducation")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> CreateResumeEducation(
            @RequestBody ResumeEducationRequestDTO resumeEducationRequestDTO) {
        try {
            resumeEducationService.CreateResumeEducation(resumeEducationRequestDTO);
            return ResponseEntity.status(HttpStatus.CREATED).body("ResumeEducation created successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PutMapping("/UpdatedResumeEducation/{idResumeEducation}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> UpdatedResumeEducation(@RequestBody ResumeEducationRequestDTO resumeEducationRequestDTO,
            @PathVariable String idResumeEducation) {
        try {
            resumeEducationService.UpdatedResumeEducation(resumeEducationRequestDTO, idResumeEducation);
            return ResponseEntity.status(HttpStatus.OK).body("resumeEducation updated successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @DeleteMapping("/DeleteResumeEducation/{idResumeEducation}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> DeleteResumeEducation(@PathVariable String idResumeEducation) {
        try {
            resumeEducationService.DeleteResumeEducationt(idResumeEducation);
            return ResponseEntity.status(HttpStatus.OK).body("ResumeEducation deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
}
