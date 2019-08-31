/*
package com.example.jwt.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
public class MyUserDetailsServiceImpl implements UserDetailsService {

    private Logger logger = LoggerFactory.getLogger(getClass());

//    private final UserService userService;
//
//    public MyUserDetailsServiceImpl(UserService userService) {
//        this.userService = userService;
//    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("登陆用户名：" + username);

        //根据用户名查找用户信息
//        String password = userService.getPassword(username);

        Collection<GrantedAuthority> adminAuth = new ArrayList<>();
        adminAuth.add(new SimpleGrantedAuthority("ROLE_ADMIN"));

        //根据查找到的用户信息判断用户是否被冻结
        return new User(username, "123",true,true,true,
                true, adminAuth);
    }

  isAccountNonExpired(); 账户没有过期

     isAccountNonLocked();  账户是否被冻结，一般是可以恢复的

     isCredentialsNonExpired(); 密码是否过期

     isEnabled();   用户是否被删除，假删，被删除一般是不能恢复的


}
*/
