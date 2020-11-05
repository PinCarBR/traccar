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

    private String oidcAuthIss;
    private String oidcAuthAud;
    private String oidcJwksFormat;
    private SigningKeyResolver signingKeyResolver;
    private int usersDefaultDeviceLimit;
    private int usersDefaultExpirationDays;

    public OidcProvider(Config config) {
        this.oidcAuthIss = config.getString(Keys.OIDCAUTHISS);
        this.oidcAuthAud = config.getString(Keys.OIDCAUTHAUD);
        this.oidcJwksFormat = config.getString(Keys.OIDCJWKSFORMAT, "standard");
        switch (oidcJwksFormat.toLowerCase()) {
            case "x5cset":
                this.signingKeyResolver = new X5cSetSigningKeyResolver(config);
            default:
                this.signingKeyResolver = new StdJwksSigningKeyResolver(config);
        }
        this.usersDefaultDeviceLimit = config.getInteger(Keys.USERSDEFAULTDEVICELIMIT, -1);
        this.usersDefaultExpirationDays = config.getInteger(Keys.USERSDEFAULTEXPIRATIONDAYS);
    }

    public Claims validateToken(String tokenString) {
        try {
            return Jwts.parserBuilder()
                    .requireIssuer(oidcAuthIss)
                    .requireAudience(oidcAuthAud)
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
        user.setDeviceLimit(usersDefaultDeviceLimit);
        if (usersDefaultExpirationDays > 0) {
            user.setExpirationTime(
                    new Date(System.currentTimeMillis() + (long) usersDefaultExpirationDays * 24 * 3600 * 1000)
            );
        }
        return user;
    }
}
