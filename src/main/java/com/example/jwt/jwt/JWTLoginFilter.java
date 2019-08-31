package com.example.jwt.jwt;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.JwtBuilder;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * 验证用户名密码正确后，生成一个token，并将token返回给客户端
 * 该类继承自UsernamePasswordAuthenticationFilter，重写了其中的2个方法 ,
 * attemptAuthentication：接收并解析用户凭证。
 * successfulAuthentication：用户成功登录后，这个方法会被调用，我们在这个方法里生成token并返回。
 *
 * @author Mark
 */
public class JWTLoginFilter extends UsernamePasswordAuthenticationFilter {

    private static String stringKey = "7qZVN0BV6oofJh0kD4llKsM5vs9kytPu";
    private static byte[] encodeKey = Base64.decodeBase64(stringKey);
    private static SecretKey key = new SecretKeySpec(encodeKey, 0, encodeKey.length, "AES");

    private AuthenticationManager authenticationManager;

    public JWTLoginFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>()));

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication auth) {
        Claims claims = Jwts.claims();
        claims.put("role", auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));

        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(auth.getName())
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 60 * 24 * 1000))
                .signWith(SignatureAlgorithm.HS512, key).compact();

        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        String str = "{\"token\":\"" + token + "\"}";
        PrintWriter out;
        try {
            out = response.getWriter();
            out.print(str);
            out.flush();
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String acquire(String name) {
        System.out.println("name == " + name);
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        //生成JWT的时间
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        //有效时间 2小时
        long ttlMillis = 1000 * 60 * 60 * 2;
        long expMillis = nowMillis + ttlMillis;
        Date exp = new Date(expMillis);

        JwtBuilder builder = Jwts.builder()
                //设置Header
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("alg", "HS256")
                //iat: jwt的签发时间
                .setIssuedAt(now)
                //如果有私有声明，一定要先设置这个自己创建的私有的声明，这个是给builder的claim赋值，一旦写在标准的声明赋值之后，就是覆盖了那些标准的声明的
                .claim("name", name)
//                .claim("rdSession", rdSession)
                //sub(Subject)：代表这个JWT的主体，即它的所有人，这个是一个json格式的字符串，
                // 可以存放什么userid，roldid之类的，作为什么用户的唯一标志。
                // .setSubject(rdSession)
                //设置过期时间
                .setExpiration(exp)
                .signWith(signatureAlgorithm, key);
        return builder.compact();
    }
}