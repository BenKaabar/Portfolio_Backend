package com.example.protfolio.Services.Service;

import java.util.List;

import com.example.protfolio.Entites.Services;
import com.example.protfolio.RequestDTO.ServiceRequestDTO;

public interface ServiceService {
    void CreateService(ServiceRequestDTO serviceRequestDTO);

    void DeleteService(String idService);

    void UpdateService(ServiceRequestDTO serviceRequestDTO, String idService);

    List<Services> AllService();
}
