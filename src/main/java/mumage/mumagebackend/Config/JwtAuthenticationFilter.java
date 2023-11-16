package mumage.mumagebackend.Config;

import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mumage.mumagebackend.service.JwtService;
import mumage.mumagebackend.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtservice;
    private final UserService userService;

    @Override
    protected void doFilterInternal(
            @Nonnull HttpServletRequest request,
            @Nonnull HttpServletResponse response,
            @Nonnull FilterChain filterChain) throws ServletException, IOException {

        if (request.getRequestURI().equals("/user/login")) {
            filterChain.doFilter(request, response);
            return;
        }

        final Optional<String> jwt = jwtservice.extractAccessToken(request);
        log.info("token 값 유효성 체크 시작 토큰 : " + jwt);

        if (jwt.isPresent() && SecurityContextHolder.getContext().getAuthentication() == null
                && jwtservice.validateToken(jwt.get())) {
            String loginId = jwtservice.extractLoginId(jwt.get());
            UserDetails userDetails = userService.loadUserByUsername(loginId);
            Authentication authentication = jwtservice.getAuthentication(userDetails);

            log.info("auth 발급 성공");

            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(securityContext);
        }

        filterChain.doFilter(request, response);
    }

}
