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

import com.example.protfolio.Entites.Work;
import com.example.protfolio.RequestDTO.WorkRequestDTO;
import com.example.protfolio.Services.Work.WorkService;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@AllArgsConstructor
@RestController
@CrossOrigin(origins = "https://portfolio-benkaabar.netlify.app/")
@RequestMapping(path = "/Work")
@Slf4j
public class WorkController {
    @Autowired
    private WorkService workService;

    @GetMapping("/AllWork")
    public ResponseEntity<?> AllWork() {
        try {
            List<Work> works = workService.AllWork();
            return ResponseEntity.ok(works);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PostMapping("/CreateWork")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")    
    public ResponseEntity<String> CreateWork(@RequestParam("workRequestDTO") String workDTOJson,
            @RequestParam("photoWork") MultipartFile photoWork) {
        try {
            WorkRequestDTO workDTO = new ObjectMapper().readValue(workDTOJson,
                    WorkRequestDTO.class);
            workService.CreateWork(workDTO, photoWork);
            return ResponseEntity.status(HttpStatus.CREATED).body("Work created successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PutMapping("/UpdateWork/{idWork}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> UpdatedWork(
            @RequestParam("workRequestDTO") String workDTOJson,
            @RequestParam("photoWork") MultipartFile photoWork,
            @PathVariable String idWork) {
        try {
            WorkRequestDTO workDTO = new ObjectMapper().readValue(workDTOJson,
                    WorkRequestDTO.class);
            workService.UpdatedWork(workDTO, idWork, photoWork);
            return ResponseEntity.status(HttpStatus.OK).body("Work updated successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @DeleteMapping("/DeleteWork/{idWork}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> DeleteWork(@PathVariable String idWork) {
        try {
            workService.DeleteWork(idWork);
            return ResponseEntity.status(HttpStatus.OK).body("Work deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
}
