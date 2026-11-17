package br.com.bry.challenge.support;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** In-memory PKCS12 variants for service and HTTP regression tests. */
public final class SigningMaterialFixtures {
    private SigningMaterialFixtures() {
    }

    public static byte[] withMismatchedCertificate(byte[] pkcs12, String alias, char[] password) throws Exception {
        KeyStore original = load(pkcs12, password);
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var unrelatedKeys = generator.generateKeyPair();
        var provider = new BouncyCastleProvider();
        var name = new X500Name("CN=Unrelated signing key");
        var certificate = new JcaX509CertificateConverter().setProvider(provider).getCertificate(
                new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                        Date.from(Instant.parse("2020-01-01T00:00:00Z")),
                        Date.from(Instant.parse("2040-01-01T00:00:00Z")), name, unrelatedKeys.getPublic())
                        .build(new JcaContentSignerBuilder("SHA512withRSA").setProvider(provider)
                                .build(unrelatedKeys.getPrivate())));

        KeyStore mismatched = KeyStore.getInstance("PKCS12");
        mismatched.load(null, password);
        mismatched.setKeyEntry(alias, original.getKey(alias, password), password, new Certificate[]{certificate});
        return encode(mismatched, password);
    }

    public static byte[] withDifferentlyProtectedSecretKey(byte[] pkcs12, char[] password) throws Exception {
        KeyStore store = load(pkcs12, password);
        store.setEntry("unrelated-aes-key", new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[16], "AES")),
                new KeyStore.PasswordProtection("different-aes-password".toCharArray()));
        return encode(store, password);
    }

    private static KeyStore load(byte[] pkcs12, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new ByteArrayInputStream(pkcs12), password);
        return store;
    }

    private static byte[] encode(KeyStore store, char[] password) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        store.store(output, password);
        return output.toByteArray();
    }
}
