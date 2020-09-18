package org.traccar.authorization;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.Context;
import org.traccar.config.Config;
import org.traccar.config.Keys;

import javax.json.JsonObject;


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class X5cSetSigningKeyResolver extends SigningKeyResolverAdapter {

    private static final Logger LOGGER = LoggerFactory.getLogger(X5cSetSigningKeyResolver.class);

    private String OidcJwksUri;

    public X5cSetSigningKeyResolver(Config config) {
        this.OidcJwksUri = config.getString(Keys.OidcJwksUri, null);
    }

    @Override
    public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
        Key key = null;
        try {
            key = getSigningKey(jwsHeader.getKeyId());
        } catch (CertificateException e) {
            LOGGER.warn(String.valueOf(e));
        }
        return key;
    }

    private PublicKey getSigningKey(String kid) throws CertificateException {

        JsonObject jwks = Context
                .getClient()
                .target(OidcJwksUri)
                .request()
                .get(JsonObject.class);

        String publicKeyContent = jwks.getString(kid);
        InputStream inputStream = new ByteArrayInputStream(publicKeyContent.getBytes(StandardCharsets.UTF_8));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inputStream);

        return cert.getPublicKey();
    }
}
