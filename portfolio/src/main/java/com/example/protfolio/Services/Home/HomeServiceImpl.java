package com.example.protfolio.Services.Home;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.protfolio.Entites.Home;
import com.example.protfolio.Repository.HomeRepository;
import com.example.protfolio.RequestDTO.HomeRequestDTO;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class HomeServiceImpl implements HomeService{

    @Autowired
    private HomeRepository homeRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // @Override
    // public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    //     log.info("Loading user by username: {}", username);
    //     Home home = homeRepository.findByGmail(username);
    //     if (home == null) {
    //         throw new UsernameNotFoundException("User not found with email: " + username);
    //     }
    //     log.info("User found: {}", home.getGmail());
    //     return new HomeUserDetails(home);
    // }

    @Override
    public void CreateHome(HomeRequestDTO homeRequestDTO, MultipartFile image, MultipartFile CVfile)
            throws IOException {
        Home newHome = new Home();
        newHome.setSpeciality(homeRequestDTO.getSpeciality());
        newHome.setName(homeRequestDTO.getName());
        newHome.setDescription(homeRequestDTO.getDescription());
        newHome.setAddress(homeRequestDTO.getAddress());
        newHome.setGitHub(homeRequestDTO.getGitHub());
        newHome.setGmail(homeRequestDTO.getGmail());
        newHome.setLanguage(homeRequestDTO.getLanguage());
        newHome.setLinkedIn(homeRequestDTO.getLinkedIn());
        newHome.setWhatsApp(homeRequestDTO.getWhatsApp());
        newHome.setNationnality(homeRequestDTO.getNationnality());
        newHome.setPassword(passwordEncoder.encode(homeRequestDTO.getPassword()));
        if (CVfile != null && !CVfile.isEmpty()) {
            newHome.setNameCvFile(CVfile.getOriginalFilename());
            newHome.setCvFile(CVfile.getBytes());
            newHome.setTypeCvFile(CVfile.getContentType());
        }
        if (image != null && !image.isEmpty()) {
            newHome.setNamephoto(image.getOriginalFilename());
            newHome.setFilephoto(image.getBytes());
            newHome.setTypephoto(image.getContentType());
        }
        log.info("Home added successfully.");
        homeRepository.save(newHome);
    }

    @Override
    public void UpdateHome(HomeRequestDTO homeRequestDTO, String idHome, MultipartFile image, MultipartFile CVfile)
            throws IOException {
        Home currentHome = homeRepository.findById(idHome).get();
        if (homeRequestDTO.getSpeciality() != null) {
            currentHome.setSpeciality(homeRequestDTO.getSpeciality());
        }
        if (homeRequestDTO.getName() != null) {
            currentHome.setName(homeRequestDTO.getName());
        }
        if (homeRequestDTO.getDescription() != null) {
            currentHome.setDescription(homeRequestDTO.getDescription());
        }
        if (homeRequestDTO.getAddress() != null) {
            currentHome.setAddress(homeRequestDTO.getAddress());
        }
        if (homeRequestDTO.getGitHub() != null) {
            currentHome.setGitHub(homeRequestDTO.getGitHub());
        }
        if (homeRequestDTO.getPassword() != null) {
            currentHome.setPassword(passwordEncoder.encode(homeRequestDTO.getPassword()));
        }
        if (homeRequestDTO.getGmail() != null) {
            currentHome.setGmail(homeRequestDTO.getGmail());
        }
        if (homeRequestDTO.getLanguage() != null) {
            currentHome.setLanguage(homeRequestDTO.getLanguage());
        }
        if (homeRequestDTO.getLinkedIn() != null) {
            currentHome.setLinkedIn(homeRequestDTO.getLinkedIn());
        }
        if (homeRequestDTO.getWhatsApp() != null) {
            currentHome.setWhatsApp(homeRequestDTO.getWhatsApp());
        }
        if (homeRequestDTO.getNationnality() != null) {
            currentHome.setNationnality(homeRequestDTO.getNationnality());
        }
        if (CVfile != null && !CVfile.isEmpty()) {
            currentHome.setNameCvFile(CVfile.getOriginalFilename());
            currentHome.setCvFile(CVfile.getBytes());
            currentHome.setTypeCvFile(CVfile.getContentType());
        }
        if (image != null && !image.isEmpty()) {
            currentHome.setNamephoto(image.getOriginalFilename());
            currentHome.setFilephoto(image.getBytes());
            currentHome.setTypephoto(image.getContentType());
        }
        log.info("Home updated successfully.");
        homeRepository.save(currentHome);
    }

    @Override
    public void DeleteHome(String idHome) {
        Home deleteHome = homeRepository.findById(idHome).get();
        log.info("Home deleted successfully.");
        homeRepository.delete(deleteHome);
    }

    @Override
    public List<Home> AllHome() {
        List<Home> homes = homeRepository.findAll();
        log.info("found " + homes.size() + " homes");
        return homes;
    }

}
