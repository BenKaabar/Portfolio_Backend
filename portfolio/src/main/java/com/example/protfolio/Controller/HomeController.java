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

import com.example.protfolio.Entites.Home;
import com.example.protfolio.RequestDTO.HomeRequestDTO;
import com.example.protfolio.Services.Home.HomeService;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@AllArgsConstructor
@RestController
@CrossOrigin(origins = "https://portfolio-benkaabar.netlify.app")

@RequestMapping(path = "/Home")
@Slf4j
public class HomeController {
    @Autowired
    private HomeService homeService;

    @GetMapping("/AllHome")
    public ResponseEntity<?> AllHome() {
        try {
            List<Home> homes = homeService.AllHome();
            return ResponseEntity.ok(homes);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PostMapping("/CreateHome")
    // @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> CreateHome(@RequestParam("homeRequestDTO") String homeDTOJson,
            @RequestParam("HomeImage") MultipartFile image,
            @RequestParam("HomeCVfile") MultipartFile CVfile) {
        try {
            HomeRequestDTO homeDTO = new ObjectMapper().readValue(homeDTOJson, HomeRequestDTO.class);
            homeService.CreateHome(homeDTO, image, CVfile);
            return ResponseEntity.status(HttpStatus.CREATED).body("Home created successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PutMapping("/UpdatedHome/{idHome}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> UpdatedHome(@RequestParam("homeRequestDTO") String homeDTOJson,
            @RequestParam(value = "HomeImage", required = false) MultipartFile image,
            @RequestParam(value = "HomeCVfile", required = false) MultipartFile CVfile,
            @PathVariable String idHome) {
        try {
            HomeRequestDTO homeDTO = new ObjectMapper().readValue(homeDTOJson, HomeRequestDTO.class);
            homeService.UpdateHome(homeDTO, idHome, image, CVfile);
            return ResponseEntity.status(HttpStatus.OK).body("Home updated successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @DeleteMapping("/DeleteHome/{idHome}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> DeleteHome(@PathVariable String idHome) {
        try {
            homeService.DeleteHome(idHome);
            return ResponseEntity.status(HttpStatus.OK).body("Home deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
}
