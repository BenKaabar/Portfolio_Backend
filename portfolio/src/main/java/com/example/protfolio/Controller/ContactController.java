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
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.protfolio.Entites.Contact;
import com.example.protfolio.RequestDTO.ContactRequestDTO;
import com.example.protfolio.Services.Contact.ContactService;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
@CrossOrigin(origins = "https://portfolio-benkaabar.netlify.app/")

@AllArgsConstructor
@RestController
@RequestMapping(path = "/Contact")
@Slf4j
public class ContactController {
    @Autowired
    private ContactService contactService;
    @PostMapping("/CreateContact")
    public ResponseEntity<String> CreateContact(@RequestBody ContactRequestDTO contactRequestDTO) {
        try {
            contactService.CreateContact(contactRequestDTO);
            return ResponseEntity.status(HttpStatus.CREATED).body("Contact created successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @GetMapping("/AllContact")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<?> AllContact() {
        try {
            List<Contact> Contact = contactService.AllContact();
            return ResponseEntity.ok(Contact);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }


    @DeleteMapping("/DeleteContact/{idContact}")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<String> DeleteContact(@PathVariable String idContact) {
        try {
            contactService.DeleteContact(idContact);
            return ResponseEntity.status(HttpStatus.OK).body("Contact deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }
}
