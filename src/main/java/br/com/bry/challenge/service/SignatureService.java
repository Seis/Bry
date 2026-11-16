package br.com.bry.challenge.service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignatureService {
    private static final Logger log = LoggerFactory.getLogger(SignatureService.class);

    /** Returns attached CMS bytes. Null arguments are rejected with IllegalArgumentException. */
    public byte[] sign(byte[] document, byte[] pkcs12, String alias, char[] password)
            throws IOException, GeneralSecurityException, CMSException, OperatorCreationException {
        requireArgument(document, "document");
        requireArgument(pkcs12, "pkcs12");
        requireArgument(alias, "alias");
        requireArgument(password, "password");

        long startedAt = System.nanoTime();
        log.debug("Starting attached CMS signing: documentBytes={}, algorithm=SHA512withRSA", document.length);

        KeyStore store = getStore(pkcs12, password);
        PrivateKey pk = getPk(alias, password, store);
        if (!(store.getCertificate(alias) instanceof X509Certificate certificate)) {
            throw new GeneralSecurityException("No X.509 certificate found for alias: " + alias);
        }
        log.debug("PKCS12 private key and signer certificate loaded");

        SignerInfoGenerator signerInfo = new JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider(new BouncyCastleProvider())
                .build("SHA512withRSA", pk, certificate);

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(signerInfo);
        generator.addCertificates(new JcaCertStore(List.of(certificate)));

        CMSProcessableByteArray content = new CMSProcessableByteArray(document);
        byte[] result = generator.generate(content, true).getEncoded();
        log.info("Attached CMS signing completed: documentBytes={}, signatureBytes={}, durationMs={}",
                document.length, result.length, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt));
        return result;
    }

    private static void requireArgument(Object value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
    }

    private static PrivateKey getPk(String alias, char[] password, KeyStore store)
            throws GeneralSecurityException {
        if (!store.containsAlias(alias)) {
            throw new GeneralSecurityException("Alias not found: " + alias);
        }

        Key key;
        try {
            key = store.getKey(alias, password);
        } catch (UnrecoverableKeyException cause) {
            UnrecoverableKeyException error = new UnrecoverableKeyException("Unable to recover private key for alias: " + alias);
            error.initCause(cause);
            throw error;
        }

        if (!(key instanceof PrivateKey privateKey)) {
            throw new InvalidKeyException("No private key found for alias: " + alias);
        }
        if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new InvalidKeyException("An RSA private key is required");
        }
        return privateKey;
    }

    private static KeyStore getStore(byte[] pkcs12, char[] password)
            throws IOException, GeneralSecurityException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new ByteArrayInputStream(pkcs12), password);
        return store;
    }
}
