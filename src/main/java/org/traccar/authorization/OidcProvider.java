package org.traccar.authorization;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.config.Config;
import org.traccar.config.Keys;
import org.traccar.model.User;


public class OidcProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(OidcProvider.class);

    private String OidcAuthIss;
    private String OidcAuthAud;
    private SigningKeyResolver signingKeyResolver;

    public OidcProvider(Config config) {
        this.OidcAuthIss = config.getString(Keys.OidcAuthIss);
        this.OidcAuthAud = config.getString(Keys.OidcAuthAud);
        this.signingKeyResolver = new X509CertSigningKeyResolver(config);
    }

    public String validateToken(String tokenString) {
        try {
            return Jwts.parserBuilder()
                    .requireIssuer(OidcAuthIss)
                    .requireAudience(OidcAuthAud)
                    .setSigningKeyResolver(signingKeyResolver)
                    .build()
                    .parseClaimsJws(tokenString)
                    .getBody()
                    .get("email", String.class);
        } catch (JwtException ex) {
            LOGGER.warn("Invalid id token provided");
            return null;
        }
    }

    public User getUser(String accountName) {
        User user = new User();
        user.setLogin(accountName);
        user.setName(accountName);
        user.setEmail(accountName);
        user.setAdministrator(false);
        return user;
    }
}
