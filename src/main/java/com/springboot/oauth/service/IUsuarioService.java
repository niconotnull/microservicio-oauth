package com.springboot.oauth.service;

import com.springboot.commons.usuarios.entity.AdministradorEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

public interface IUsuarioService {

    AdministradorEntity findByUsername(String username);

    AdministradorEntity update(AdministradorEntity usuarios, Integer id);
}
