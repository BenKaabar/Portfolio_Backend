package com.example.protfolio.Controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.protfolio.Entites.Services;
import com.example.protfolio.RequestDTO.ServiceRequestDTO;
import com.example.protfolio.Services.Service.ServiceService;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.PathVariable;

@AllArgsConstructor
@RestController
@CrossOrigin(origins = "https://astonishing-sherbet-feb009.netlify.app")
@RequestMapping(path = "/Service")
@Slf4j
public class ServiceController {
    @Autowired
    private ServiceService serviceService;

    @GetMapping("/AllServices")
    public ResponseEntity<?> AllServices() {
        try {
            List<Services> services = serviceService.AllService();
            return ResponseEntity.ok(services);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PostMapping("/CreateServices")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> CreateServices(@RequestBody ServiceRequestDTO serviceRequestDTO) {
        try {
            serviceService.CreateService(serviceRequestDTO);
            return ResponseEntity.status(HttpStatus.CREATED).body("service created successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PutMapping("/UpdatedService/{idService}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> UpdatedService(@RequestBody ServiceRequestDTO serviceRequestDTO,
            @PathVariable String idService) {
        try {
            serviceService.UpdateService(serviceRequestDTO, idService);
            return ResponseEntity.status(HttpStatus.OK).body("service updated successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @DeleteMapping("/DeleteService/{idService}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> DeleteService(@PathVariable String idService) {
        try {
            serviceService.DeleteService(idService);
            return ResponseEntity.status(HttpStatus.OK).body("service deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
}
