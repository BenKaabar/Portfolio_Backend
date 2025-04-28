package com.example.protfolio.Services.Work;

import java.io.IOException;
import java.util.List;

import org.springframework.web.multipart.MultipartFile;

import com.example.protfolio.Entites.Work;
import com.example.protfolio.RequestDTO.WorkRequestDTO;

public interface WorkService {
    void CreateWork(WorkRequestDTO WorkRequestDTO, MultipartFile photoWork) throws IOException;

    void UpdatedWork(WorkRequestDTO WorkRequestDTO, String idWork, MultipartFile photoWork)
            throws IOException;

    void DeleteWork(String idWork);

    List<Work> AllWork();
}
