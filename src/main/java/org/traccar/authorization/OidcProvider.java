package org.traccar.authorization;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.model.User;

import java.util.Date;


public class OidcProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(OidcProvider.class);

    private String OidcAuthIss;
    private String OidcAuthAud;
    private String OidcJwksFormat;
    private SigningKeyResolver signingKeyResolver;
    private int UsersDefaultDeviceLimit;
    private int UsersDefaultExpirationDays;

    public OidcProvider(Config config) {
        this.OidcAuthIss = config.getString(Keys.OidcAuthIss);
        this.OidcAuthAud = config.getString(Keys.OidcAuthAud);
        this.OidcJwksFormat = config.getString(Keys.OidcJwksFormat, "standard");
        switch (OidcJwksFormat.toLowerCase()) {
            case "x5cset":
                this.signingKeyResolver = new X5cSetSigningKeyResolver(config);
            default:
                this.signingKeyResolver = new StdJwksSigningKeyResolver(config);
        }
        this.UsersDefaultDeviceLimit = config.getInteger(Keys.UsersDefaultDeviceLimit, -1);
        this.UsersDefaultExpirationDays = config.getInteger(Keys.UsersDefaultExpirationDays);
    }

    public Claims validateToken(String tokenString) {
        try {
            return Jwts.parserBuilder()
                    .requireIssuer(OidcAuthIss)
                    .requireAudience(OidcAuthAud)
                    .setSigningKeyResolver(signingKeyResolver)
                    .build()
                    .parseClaimsJws(tokenString)
                    .getBody();
        } catch (JwtException ex) {
            LOGGER.warn("Invalid id token provided");
            return null;
        }
    }

    public User getUser(Claims claims) {
        User user = new User();
        user.setLogin(claims.get("email", String.class));
        user.setName(claims.get("name", String.class));
        user.setEmail(claims.get("email", String.class));
        user.setAdministrator(false);
        user.setDeviceLimit(UsersDefaultDeviceLimit);
        user.setExpirationTime(
                new Date(System.currentTimeMillis() + (long) UsersDefaultExpirationDays * 24 * 3600 * 1000)
        );
        return user;
    }
}
