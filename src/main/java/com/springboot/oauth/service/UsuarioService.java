package com.springboot.oauth.service;

import com.springboot.commons.usuarios.entity.AdministradorEntity;
import com.springboot.oauth.client.UsuarioFeignClient;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UsuarioService implements IUsuarioService,UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(UsuarioService.class);

    @Autowired
    private UsuarioFeignClient usuarioClient;

    /**
     * Este es el primer método que se configuro para realizar la autenticación
     *
     * Se debéra de utilizar la implementación de UserDetailsService
     *
     * Esta implementación se encarga de autenticar de obtener al usuario por el username
     * independientemente si se esta utilizando JPA, JDBC etc
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            AdministradorEntity usuario = usuarioClient.findByUsername(username);

            List<GrantedAuthority> authorities = usuario.getRoles()
                    .stream()
                    .map(role -> new SimpleGrantedAuthority(role.getNombre()))
                    .peek(authority -> log.info("Rol e : " + authority.getAuthority()))
                    .collect(Collectors.toList());

            log.info("Usuario autenticado : " + username);
            return new User(usuario.getUsername(), usuario.getPassword(), usuario.getEnabled(), true, true, true, authorities);
        } catch (FeignException e) {
            log.error("Error en el login, no existe el usuario '" + username + "' en el sistema");
            throw new UsernameNotFoundException("Error en el login, no existe el usuario '" + username + "' en el sistema");
        }
    }

    @Override
    public AdministradorEntity findByUsername(String username) {
        return usuarioClient.findByUsername(username);
    }

    @Override
    public AdministradorEntity update(AdministradorEntity usuario, Integer id) {
        return usuarioClient.update(usuario,id);
    }
}
