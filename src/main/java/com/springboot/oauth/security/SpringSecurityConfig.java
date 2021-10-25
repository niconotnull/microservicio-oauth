package com.springboot.oauth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * Esta clase permite registrar en  la clase AuthenticationManager de spring-security
     * la clase UsuarioService que implementa la clase UserDetailsService para que se pueda
     * realizar el proceso de autenticación utilizando el cliente Feign mediante comunicación apiREST
     */


    /**
     *  Paso 1:  primero se deberá de inyectar la clase  UserDetailsService implementado
     *  con el cliente HTTP Feign el cual se comunica con el microservicio de usuarios para
     *  obtener el usuario por el username. Se utiliza la interfaz genérica UserDetailsService
     *
     *  Al inyectar esta dependencia inyectara el componente concreto que se ha definido como UsuarioService
     *  que es del tipo genérico UserDetailsService y como UsuarioService esta anotado con @Service spring ira
     *  a buscar un componente que implemente la interfaz UserDetailsService y lo inyectará a partir de esta instrucción
     *
     *  Autowired
     *  private UserDetailsService usuarioService;
     *
     */
    @Autowired
    private UserDetailsService usuarioService;

    @Autowired
    private AuthenticationEventPublisher eventPublisher;

    /**
     * Paso 2: Se deberá de registrar el usuarioService en AuthenticationManagerBuilder,
     * AuthenticationManagerBuilder se deberá de inyectar a través del método,
     * auth permite registrar a través de userDetailsService el usuarioService
     * se deberá de encriptar el password para dar mayor seguridad al password
     */

    @Override
    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       auth.userDetailsService(usuarioService).passwordEncoder(passwordEncoder())
               .and().authenticationEventPublisher(eventPublisher);

    }


    /**
     * Paso 4: configurar el AuthenticationManager se deberá también registrar como un
     * componente de spring con @Bean para que posteriormente se pueda inyectar en la
     * configuración del servidor de autorización de oauth2
     */
    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    /**
     * Paso 3:  Se utiliza BCryptPasswordEncoder para encriptar el password
     * se anota con  @Bean para que se guarde en el contenedor de spring y se pueda
     * utilizar para encripatar los passwords
     *
     * Permite  @Bean es una anotación que permite registrar en el contenedor de spring
     * objetos y/o componentes muy parecido a la anotación @Component o @Service pero la diferencia es que
     * nos permite guardar nuestras propias clases que estamos creando es decir estamos creando
     * nuestra propia implementación, pero con el bean es vía método lo que retorna el método es lo
     * que se va a registrar en spring
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }

}
