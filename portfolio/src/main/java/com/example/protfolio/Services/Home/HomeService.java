package com.example.protfolio.Services.Home;

import java.io.IOException;
import java.util.List;

import org.springframework.web.multipart.MultipartFile;

import com.example.protfolio.Entites.Home;
import com.example.protfolio.RequestDTO.HomeRequestDTO;

public interface HomeService {
    void CreateHome(HomeRequestDTO homeRequestDTO, MultipartFile image, MultipartFile CVfile) throws IOException;

    void UpdateHome(HomeRequestDTO homeRequestDTO, String idHome, MultipartFile image, MultipartFile CVfile)
            throws IOException;

    void DeleteHome(String idHome);

    List<Home> AllHome();
}
