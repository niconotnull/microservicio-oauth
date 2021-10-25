package com.springboot.oauth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.Arrays;
import java.util.Base64;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    /**
     * En esta clase se realiza la configuración  del servidor de autorización, que se encargara
     * de todo el proceso del login por el lado de ouath2, generacón del token desde el proceso de
     * autenticación generar el token validarlo, utilizando el AuthenticationManager de la clase de
     * SpringSecurutyConfig
     */

    //    @Value("${config.security.oauth.jwt.key}")
    private String llaveJwt = "123445jkdjsdksdjaskjdlkajdadjasddisinid90sd9js9d9sdcsdjc9sdasd8j9as8d98sdjc98sdjc9asdjsdsdsdsdwewwwwwwwwwwwwwwwwwwwwewsd98sadjsd9sd9d9d9s9ds9asasasasasd9d";

    /**
     * Se realizo la configuración previamente en el Paso 3 de SpringSecurityConfig
     */
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    /**
     * Se realizo la configuración previamente en el Paso 4 de SpringSecurityConfig
     */
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private InfoAdicionalToken infoAdicionalToken;
    /**
     *Paso 5: Realizar la configuración de  AuthorizationServerSecurityConfigurer
     * que son los permisos que van a tener nuestros endPoints del servidor de autorización
     * para generar el token y también para validar el token
     * tokenKeyAccess= permitir a todos
     * checkTokenAccess = valida el token que requiere autenticacion
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
      security.tokenKeyAccess("permitAll()")
              .checkTokenAccess("isAuthenticated()");
    }

    /**
     * Paso 4: Se configuran los clientes, es decir las aplicaciones frontEnd que van acceder
     * que van a acceder a los nuestros microservicios, en caso de que se tengan varios
     * clientes se deberá de registrar uno por uno, ccn las siguientes propiedades
     * clientId, password, no solo se realiza la autenticación con los usuarios de nuestros
     * backEnd  sino también con las credenciales de la aplicación cliente que se comunicará
     * con nuestro backend.
     * scopes= alcance de la aplicación cliente es decir de lectura y escritura
     * authorizedGrantTypes=  tipo de concesión que tendrá nuestra  autenticación
     * es decir como se obtendrá el token se utiliza el password  cuando es con credenciales es
     * decir cuando los usuarios existen en nuestro sistema del backend
     *
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory().withClient(llaveJwt)
                .secret(passwordEncoder.encode("123456"))
                .scopes("read","write")
                .authorizedGrantTypes("password", "refresh_token")
                .accessTokenValiditySeconds(3600)
                .refreshTokenValiditySeconds(3600)
                .and()
                .withClient("androidapp")
                .secret(passwordEncoder.encode("123456"))
                .scopes("read","write")
                .authorizedGrantTypes("password", "refresh_token")
                .accessTokenValiditySeconds(3600)
                .refreshTokenValiditySeconds(3600);
    }


    /**
     * Paso 1:  Aquí se deberá de configurar el AuthenticationManager
     * authenticationManager: se registra el authenticationManager
     * tokenStore : permite
     * accessTokenConverter: componente que se encarga de guardar los datos del usuario como el username, roles
     * es decir cualquier tipo de información extra que se desee agregar al token  que se conoce como "claims"
     * por otra parte accessTokenConverter se encarga de tomar estos valores y convertirlos en el token en el JWT
     * codificados en base64
     *
     * Este método AuthorizationServerEndpointsConfigurer endpoints esta relacionado al endPoint de oauth2
     * del servidor de autorización  /oauth/token que es una peticón del tipo POST que va a recibir el username,password
     * el grant_type y si todo sale correcto  se generará el token y retornará un json con el token a usuario  que
     * podrá utilizar para acceder a los recursos protegidos de los microservicios, pero esa validacion se realiza en el
     * servidor de recuros
     *
     * Nota : tokenEnhancerChain permite unir la información del token con información adicional que requiere el token
     * para ello se requiere unir la informacion con setTokenEnhancers
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(infoAdicionalToken, accessTokenConverter()));


        endpoints.authenticationManager(authenticationManager)
                .tokenStore(tokenStore())
                .accessTokenConverter(accessTokenConverter())
                .tokenEnhancer(tokenEnhancerChain);
    }

    /**
     * Paso 3: Este componente se encarga de guardar el token y generar el
     * token con los datos del accessTokenConverter
     * recibe por argumento en el constructor accessTokenConverter
     */
    @Bean
    public JwtTokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    /**
     * Paso 2: se deberá de agregar un código secreto para firmar el token
     * tiene que ser único por que posteriomente el código secreto se
     * utilizará en el servidor de recursos para validar el token que sea el correcto
     * con la misma firma y así dar  acceso a los clientes a los recursos protegidos de nuestros microservicios
     * setSigningKey- se asigna la firma
     */
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
        tokenConverter.setSigningKey(Base64.getEncoder().encodeToString(llaveJwt.getBytes()));
        return tokenConverter;
    }
}
