package com.example.protfolio.Services.Contact;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.protfolio.Entites.Contact;
import com.example.protfolio.Entites.Home;
import com.example.protfolio.Repository.ContactRepository;
import com.example.protfolio.RequestDTO.ContactRequestDTO;
import com.example.protfolio.Services.Home.HomeService;
import com.example.protfolio.Services.Mail.EmailService;

import jakarta.mail.MessagingException;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class ContactServiceImpl implements ContactService {
    @Autowired
    private ContactRepository contactRepository;
    @Autowired
    EmailService emailService;
    @Autowired
    HomeService homeService;
    @Override
    public void CreateContact(ContactRequestDTO contactRequestDTO) {
        Contact newContact = new Contact();
        newContact.setFirstName(contactRequestDTO.getFirstName());
        newContact.setLastName(contactRequestDTO.getLastName());
        newContact.setEmail(contactRequestDTO.getEmail());
        newContact.setPhone(contactRequestDTO.getPhone());
        newContact.setMessage(contactRequestDTO.getMessage());
        newContact.setService(contactRequestDTO.getService());
        log.info("contact added successfully");
        contactRepository.save(newContact);
        Home home = homeService.AllHome().get(0);
        String Email = contactRequestDTO.getEmail();
        String Subject = "Confirmation - We have received your message";
        String Message = "Hello " + contactRequestDTO.getFirstName() + " " + contactRequestDTO.getLastName() +
                        " Thank you for reaching out. We have received your message and will get back to you soon.<br><br>"
                + "Details:<br>"
                + "<strong>Name:</strong> " + contactRequestDTO.getFirstName() + " " + contactRequestDTO.getLastName() + "<br>"
                + "<strong>Email:</strong> " + contactRequestDTO.getEmail() + "<br>"
                + "<strong>Phone:</strong> " + contactRequestDTO.getPhone() + "<br>"
                + "<strong>Service:</strong> " + contactRequestDTO.getService() + "<br>"
                + "<strong>Message:</strong> " + contactRequestDTO.getMessage() + "<br><br>"
                + "Please follow up as needed.<br><br> " 
                + "<strong>LinkedIn: </strong> " + home.getLinkedIn() + "<br>"
                + "<strong>GitHub: </strong> " + home.getGitHub() + "<br><br>"
                + "<strong>Link to my portfolio: </strong> https://portfolio-benkaabar.netlify.app/Home " + "<br><br>"
                + "Best regards";
        try {
            emailService.sendEmail(Email, Subject, Message);
            log.info("Email sent successfully to {}", Email);
        } catch (MessagingException e) {
            log.error("Failed to send email: {}", e.getMessage());
        }
    }
    

    @Override
    public void DeleteContact(String idContact) {
        Contact currentContact = contactRepository.findById(idContact).get();
        log.info("contact deleted successfully");
        contactRepository.delete(currentContact);
    }

    @Override
    public List<Contact> AllContact() {
        List<Contact> contacts = contactRepository.findAll();
        log.info("found " + contacts.size() + " contact");
        return contacts;
    }
    
}
