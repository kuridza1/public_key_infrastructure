package rs.ac.uns.ftn.pki;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
@Component
public class HeaderAuthFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String userId = request.getHeader("userId");
        String role = request.getHeader("role");

        if (userId != null && role != null) {
            // Add ROLE_ prefix for Spring Security
            String springSecurityRole = "ROLE_" + role;
            List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(springSecurityRole));

            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authToken);

            System.out.println("✅ Authentication set - User: " + userId + ", Role: " + springSecurityRole);
        }

        filterChain.doFilter(request, response);
    }
}