package com.example.protfolio.RequestDTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class ContactRequestDTO {
    private String firstName;
    private String LastName;
    private String email;
    private String phone;
    private String service;
    private String message;
}
