package com.springboot.oauth.event;

import com.springboot.commons.usuarios.entity.AdministradorEntity;
import com.springboot.oauth.service.IUsuarioService;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;


@Component
public class AuthenticationSuccessErrorHandler implements AuthenticationEventPublisher {

    private static  final Logger log = LoggerFactory.getLogger(AuthenticationSuccessErrorHandler.class);

    @Autowired
    private IUsuarioService usuarioService;

    /**
     * Esta  interfaz AuthenticationEventPublisher  permite validar el éxito y el fracaso
     * del login del usuario, se realiza una validación para no mostrar la autenticación
     * de la aplicación que se conecta.
     *
     * NOTA se realiza un a doble validacion tanto la del usuario como  la de la aplicación
     *
     * También se implemento la validación de los los 3 intentos fallidos al iniciar sesión
     * y deshabilitar el usuario, en caso contrario se valida y se actualiza el contador
     * de los intentos falliados de la tabla de ADMINISTRADOR del campo intentos al ser
     * correcto el inicio de sesión
     */

    @Override
    public void publishAuthenticationSuccess(Authentication authentication) {
        // Se valida si el client el clienFrontApp
        // Esta validación se realizo por que valida tanto el userDeLa aplicación
        // como la validacion del usuario
//         if(authentication.getName().equalsIgnoreCase("frontendapp"))
        if(authentication.getDetails() instanceof WebAuthenticationDetails){
            return;
        }
        UserDetails user = (UserDetails) authentication.getPrincipal();
        log.info("Success login : "+user.getUsername());

        AdministradorEntity usuario = usuarioService.findByUsername(authentication.getName());
        if(usuario.getIntentos() != null && usuario.getIntentos() > 0 ){
            usuario.setIntentos(0);
            usuarioService.update(usuario, usuario.getId());
        }
    }

    @Override
    public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
        log.info("Error en el login: " + exception.getMessage());
        try {
            AdministradorEntity usuario = usuarioService.findByUsername(authentication.getName());
            if (usuario.getIntentos() == null) {
                usuario.setIntentos(0);
            }
            log.info("Intento actual es de : "+usuario.getIntentos());
            usuario.setIntentos(usuario.getIntentos() + 1);
            log.info("Intento después es de : "+usuario.getIntentos());

            if(usuario.getIntentos() >= 3){
                log.info(String.format("El usuario %s ha sido deshabilitado por máxicomo de intentos.", usuario.getUsername()));
                usuario.setEnabled(false);
            }
            usuarioService.update(usuario, usuario.getId());
        } catch (FeignException e) {
            log.error(String.format("El usuario %s no existe en el sistema", authentication.getName()));
        }

    }
}
