package com.springboot.oauth.client;

import com.springboot.commons.usuarios.entity.AdministradorEntity;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

@FeignClient(name = "microservicio-administrador")
public interface UsuarioFeignClient {

    @GetMapping("/administrador/search/buscar-username")
    AdministradorEntity findByUsername(@RequestParam String username);

    @PutMapping("/administrador/{id}")
    AdministradorEntity update(@RequestBody AdministradorEntity usuarios, @PathVariable Integer id);
}
