package demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    KeycloakRestTemplateDirectAccessGrantAuthenticationProvider keycloakRestTemplateDirectAccessGrantAuthenticationProvider;

    @Autowired
    KeycloakAdminClientDirectAccessGrantAuthenticationProvider keycloakAdminClientDirectAccessGrantAuthenticationProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/greet/**").authenticated()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .defaultSuccessUrl("/greet", true)
                //.failureUrl("/login.html?error=true")
                .and()
                .logout()
                .deleteCookies("JSESSIONID")
        ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(keycloakRestTemplateDirectAccessGrantAuthenticationProvider);
//        auth.authenticationProvider(keycloakAdminClientDirectAccessGrantAuthenticationProvider);
    }
}
