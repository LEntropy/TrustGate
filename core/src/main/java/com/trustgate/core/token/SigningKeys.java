package com.trustgate.core.token;

import com.trustgate.core.crypto.KekProvider;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * The IdP's RSA token-signing key. The private key is stored on disk wrapped by the KEK,
 * the same master key that protects the database data keys.
 */
public final class SigningKeys {
    private static final byte[] AAD = "idp-signing-key".getBytes(StandardCharsets.UTF_8);

    private final String kid;
    private final PrivateKey privateKey;
    private final RSAPublicKey publicKey;

    private SigningKeys(String kid, PrivateKey privateKey, RSAPublicKey publicKey) {
        this.kid = kid;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public static SigningKeys loadOrCreate(Path file, KekProvider kek) {
        try {
            KeyFactory rsa = KeyFactory.getInstance("RSA");
            Properties p = new Properties();
            if (Files.exists(file)) {
                try (var in = Files.newInputStream(file)) {
                    p.load(in);
                }
                byte[] pkcs8 = kek.unwrap(Base64.getDecoder().decode(p.getProperty("private")), AAD);
                PrivateKey priv = rsa.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
                RSAPublicKey pub = (RSAPublicKey) rsa.generatePublic(
                        new X509EncodedKeySpec(Base64.getDecoder().decode(p.getProperty("public"))));
                return new SigningKeys(p.getProperty("kid"), priv, pub);
            }
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair kp = gen.generateKeyPair();
            String kid = "tg-" + Long.toString(System.currentTimeMillis() / 1000, 36);
            p.setProperty("kid", kid);
            p.setProperty("public", Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));
            p.setProperty("private", Base64.getEncoder().encodeToString(
                    kek.wrap(kp.getPrivate().getEncoded(), AAD)));
            if (file.getParent() != null) Files.createDirectories(file.getParent());
            try (var out = Files.newOutputStream(file)) {
                p.store(out, "TrustGate IdP signing key (private key wrapped by KEK)");
            }
            return new SigningKeys(kid, kp.getPrivate(), (RSAPublicKey) kp.getPublic());
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException("cannot load signing key " + file, e);
        }
    }

    public String kid() {
        return kid;
    }

    public PrivateKey privateKey() {
        return privateKey;
    }

    public RSAPublicKey publicKey() {
        return publicKey;
    }

    /** JSON Web Key Set (RFC 7517) published at /jwks for service providers. */
    public Map<String, Object> jwks() {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("use", "sig");
        jwk.put("alg", Jwt.ALG);
        jwk.put("kid", kid);
        jwk.put("n", b64u(publicKey.getModulus()));
        jwk.put("e", b64u(publicKey.getPublicExponent()));
        return Map.of("keys", List.of(jwk));
    }

    public static RSAPublicKey fromJwk(Map<?, ?> jwk) throws GeneralSecurityException {
        if (!"RSA".equals(jwk.get("kty"))) throw new GeneralSecurityException("not an RSA key");
        BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("n")));
        BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("e")));
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
    }

    private static String b64u(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length > 1 && b[0] == 0) b = java.util.Arrays.copyOfRange(b, 1, b.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
