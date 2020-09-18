package org.traccar.authorization;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.config.Config;
import org.traccar.config.Keys;

import java.net.URL;
import java.security.Key;
import java.security.PublicKey;
import java.util.concurrent.TimeUnit;

public class StdJwksSigningKeyResolver extends SigningKeyResolverAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(StdJwksSigningKeyResolver.class);

    private String OidcJwksUri;

    public StdJwksSigningKeyResolver(Config config) {
        this.OidcJwksUri = config.getString(Keys.OidcJwksUri, null);
    }

    @Override
    public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
        Key key = null;
        try {
            key = getSigningKey(jwsHeader.getKeyId());
        } catch (Exception e) {
            LOGGER.warn(String.valueOf(e));
        }
        return key;
    }

    private PublicKey getSigningKey(String kid) throws Exception {

        JwkProvider provider = new JwkProviderBuilder(new URL(OidcJwksUri))
                .cached(10, 24, TimeUnit.HOURS)
                .rateLimited(10, 1, TimeUnit.MINUTES)
                .build();
        ;
        Jwk jwk = provider.get(kid);

        return jwk.getPublicKey();
    }
}
