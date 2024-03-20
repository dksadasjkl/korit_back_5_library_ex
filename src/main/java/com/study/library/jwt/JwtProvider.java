package com.study.library.jwt;

import com.study.library.entity.User;
import com.study.library.repository.UserMapper;
import com.study.library.security.PrincipalUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
public class JwtProvider {

    private final Key key;
    private UserMapper userMapper;

    // @Value("${jwt.secret}") String secret yml 에 설정한 키값
    // @Autowired -> 생성자 매개변수 -> key 값 때문에
    public JwtProvider(
            @Value("${jwt.secret}") String secret,
            @Autowired UserMapper userMapper) {
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret)); // secret 인코드
        this.userMapper = userMapper;
    }

    // JWT = String
    public String generateToken(User user) {
        int userId = user.getUserId();
        String username = user.getUsername();
        Collection<? extends GrantedAuthority> authorities = user.getAuthorities(); // 권한
        Date expireDate = new Date(new Date().getTime() + (1000 * 60 * 60 * 24));

        String accessToken = Jwts.builder()
                .claim("userId", userId)
                .claim("username", username)
                .claim("authorities", authorities)
                .setExpiration(expireDate)
                .signWith(key, SignatureAlgorithm.HS256) // 암호화 (키, 알고리즘)
                .compact();

        return accessToken;
    }
    
    // springframework -> hasText(token) -> null, 공백 체크
    public String removeBearer(String token) {
        if(!StringUtils.hasText(token)) {
            return null;
        }
        return token.substring("Bearer ".length());
    }

    public Claims getClaims(String token) {
        Claims claims = null;

            claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token) //Claim 으로 변환
                    .getBody();
        return claims;
    }

    public Authentication getAuthentication(Claims claims) {
        String username = claims.get("username").toString(); // Object -> String
        User user = userMapper.findUserByUsername(username);
        if(user == null) {
            // 토큰은 유효하지만 DB 에서 USER 정보가 삭제되었을 경우
            return null;
        }
        PrincipalUser principalUser = user.toPrincipalUser();
        return new UsernamePasswordAuthenticationToken(principalUser, principalUser.getPassword(), principalUser.getAuthorities()); // 업캐스팅 되어 리턴
    }

    public String generateAuthMailToken(int userId, String toMailAddress) {
        Date expiredate = new Date(new Date().getTime() + (1000 * 60 * 5));
        return Jwts.builder()
                .claim("userId", userId)
                .claim("toMailAddress", toMailAddress)
                .setExpiration(expiredate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
}
