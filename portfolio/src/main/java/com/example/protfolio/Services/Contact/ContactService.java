package com.example.protfolio.Services.Contact;

import java.util.List;

import com.example.protfolio.Entites.Contact;
import com.example.protfolio.RequestDTO.ContactRequestDTO;

public interface ContactService {
    void CreateContact(ContactRequestDTO contactRequestDTO);

    void DeleteContact(String idContact);

    List<Contact> AllContact();

}
