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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.example.protfolio.Entites.ResumeSkills;
import com.example.protfolio.RequestDTO.ResumeSkillsRequestDTO;
import com.example.protfolio.Services.ResumeSkills.ResumeSkillsService;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@AllArgsConstructor
@RestController
@CrossOrigin(origins = "https://portfolio-benkaabar.netlify.app/")
@RequestMapping(path = "/ResumeSkills")
@Slf4j
public class ResumeSkillsController {
    @Autowired
    private ResumeSkillsService resumeSkillsService;

    @GetMapping("/AllResumeSkills")
    public ResponseEntity<?> AllResumeSkills() {
        try {
            List<ResumeSkills> resumeSkillss = resumeSkillsService.AllResumeSkills();
            return ResponseEntity.ok(resumeSkillss);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PostMapping("/CreateResumeSkills")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> CreateResumeSkills(@RequestParam("resumeSkillsRequestDTO") String resumeSkillsDTOJson,
            @RequestParam("photoSkill") MultipartFile photoSkill) {
        try {
            ResumeSkillsRequestDTO resumeSkillsDTO = new ObjectMapper().readValue(resumeSkillsDTOJson,
                    ResumeSkillsRequestDTO.class);
            resumeSkillsService.CreateResumeSkills(resumeSkillsDTO, photoSkill);
            return ResponseEntity.status(HttpStatus.CREATED).body("ResumeSkills created successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PutMapping("/UpdateResumeSkills/{idResumeSkills}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> UpdatedResumeSkills(
            @RequestParam("resumeSkillsRequestDTO") String resumeSkillsDTOJson,
            @RequestParam("photoSkill") MultipartFile photoSkill,
            @PathVariable String idResumeSkills) {
        try {
            ResumeSkillsRequestDTO resumeSkillsDTO = new ObjectMapper().readValue(resumeSkillsDTOJson,
                    ResumeSkillsRequestDTO.class);
            resumeSkillsService.UpdatedResumeSkills(resumeSkillsDTO, idResumeSkills, photoSkill);
            return ResponseEntity.status(HttpStatus.OK).body("ResumeSkills updated successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @DeleteMapping("/DeleteResumeSkills/{idResumeSkills}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> DeleteResumeSkills(@PathVariable String idResumeSkills) {
        try {
            resumeSkillsService.DeleteResumeSkills(idResumeSkills);
            return ResponseEntity.status(HttpStatus.OK).body("ResumeSkills deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
}
