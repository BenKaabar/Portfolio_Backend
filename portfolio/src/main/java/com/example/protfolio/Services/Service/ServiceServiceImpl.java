package com.example.protfolio.Services.Service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.protfolio.Entites.Services;
import com.example.protfolio.Repository.ServiceRepository;
import com.example.protfolio.RequestDTO.ServiceRequestDTO;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class ServiceServiceImpl implements ServiceService {

    @Autowired
    private ServiceRepository serviceRepository;

    @Override
    public void CreateService(ServiceRequestDTO serviceRequestDTO) {
        Services newService = new Services();
        newService.setTitle(serviceRequestDTO.getTitle());
        newService.setTechnology(serviceRequestDTO.getDescription());
        log.info("service added successfully");
        serviceRepository.save(newService);
    }

    @Override
    public void DeleteService(String idService) {
        Services currentService = serviceRepository.findById(idService).get();
        log.info("service deleted successfully");
        serviceRepository.delete(currentService);
    }

    @Override
    public void UpdateService(ServiceRequestDTO serviceRequestDTO, String idService) {
        Services currentService = serviceRepository.findById(idService).get();
        if (currentService.getTitle() != null) {
            currentService.setTitle(serviceRequestDTO.getTitle());
        }
        if (currentService.getTechnology() != null) {
            currentService.setTechnology(serviceRequestDTO.getDescription());
        }
        log.info("service updated successfully");
        serviceRepository.save(currentService);
    }

    @Override
    public List<Services> AllService() {
        List<Services> services = serviceRepository.findAll();
        log.info("found " + services.size() + " services");
        return services;
    }

}
