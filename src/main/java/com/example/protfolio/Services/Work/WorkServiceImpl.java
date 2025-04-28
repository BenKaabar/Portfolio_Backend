package com.example.protfolio.Services.Work;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.protfolio.Entites.Work;
import com.example.protfolio.Repository.WorkRepository;
import com.example.protfolio.RequestDTO.WorkRequestDTO;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class WorkServiceImpl implements WorkService {
    @Autowired
    private WorkRepository workRepository;

    @Override
    public void CreateWork(WorkRequestDTO workRequestDTO, MultipartFile photoWork) throws IOException {
        Work newWork = new Work();
        newWork.setProjectType(workRequestDTO.getProjectType());
        newWork.setTitle(workRequestDTO.getTitle());
        newWork.setShortDescription(workRequestDTO.getShortDescription());
        newWork.setLongDescription(workRequestDTO.getLongDescription());
        newWork.setMainTechnology(workRequestDTO.getMainTechnology());
        newWork.setAllTechnology(workRequestDTO.getAllTechnology());
        newWork.setGithub(workRequestDTO.getGithub());
        newWork.setVideo(workRequestDTO.getVideo());
        if (photoWork != null && !photoWork.isEmpty()) {
            newWork.setNamephotoWork(photoWork.getOriginalFilename());
            newWork.setFilephotoWork(photoWork.getBytes());
            newWork.setTypephotoWork(photoWork.getContentType());
        }
        log.info("Work added successfully");
        workRepository.save(newWork);
    }

    @Override
    public void UpdatedWork(WorkRequestDTO WorkRequestDTO, String idWork, MultipartFile photoWork) throws IOException {
        Work currentWork = workRepository.findById(idWork).get();
        if (WorkRequestDTO.getTitle() != null) {
            currentWork.setTitle(WorkRequestDTO.getTitle());
        }
        if (WorkRequestDTO.getProjectType() != null) {
            currentWork.setProjectType(WorkRequestDTO.getProjectType());
        }
        if (WorkRequestDTO.getShortDescription() != null) {
            currentWork.setShortDescription(WorkRequestDTO.getShortDescription());
        }
        if (WorkRequestDTO.getLongDescription() != null) {
            currentWork.setLongDescription(WorkRequestDTO.getLongDescription());
        }
        if (WorkRequestDTO.getMainTechnology() != null) {
            currentWork.setMainTechnology(WorkRequestDTO.getMainTechnology());
        }
        if (WorkRequestDTO.getAllTechnology() != null) {
            currentWork.setAllTechnology(WorkRequestDTO.getAllTechnology());
        }
        if (WorkRequestDTO.getVideo() != null) {
            currentWork.setVideo(WorkRequestDTO.getVideo());
        }
        if (WorkRequestDTO.getGithub() != null) {
            currentWork.setGithub(WorkRequestDTO.getGithub());
        }
        if (photoWork != null && !photoWork.isEmpty()) {
            currentWork.setNamephotoWork(photoWork.getOriginalFilename());
            currentWork.setFilephotoWork(photoWork.getBytes());
            currentWork.setTypephotoWork(photoWork.getContentType());
        }
        log.info("Work updated successfully");
        workRepository.save(currentWork);
    }

    @Override
    public void DeleteWork(String idWork) {
        Work currentWork = workRepository.findById(idWork).get();
        log.info("Work deleted successfully");
        workRepository.delete(currentWork);
    }

    @Override
    public List<Work> AllWork() {
        List<Work> Works = workRepository.findAll();
        log.info("found " + Works.size() + " Works");
        return Works;
    }

}
