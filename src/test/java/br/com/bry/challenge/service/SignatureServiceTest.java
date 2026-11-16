package br.com.bry.challenge.service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.InvalidKeyException;
import java.security.UnrecoverableKeyException;

import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.stream.Stream;

import br.com.bry.challenge.util.Utils;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.*;

class SignatureServiceTest {

    private static final String PASSWORD = "bry123456";
    private static String alias;
    private static byte[] pkcs12;
    private static byte[] document;
    private static X509Certificate expectedCertificate;

    private final SignatureService service = new SignatureService();

    @Test
    @DisplayName("Stage 2: sign doc.txt with SHA-512/RSA, attach it to CMS and save a .p7s file")
    void stage2SignsChallengeDocumentAndWritesP7s(@TempDir Path directory) throws Exception {
        byte[] signature = service.sign(document, pkcs12, alias, PASSWORD.toCharArray());
        Path signedFile = directory.resolve("doc.p7s");
        Files.write(signedFile, signature);

        assertTrue(Files.isRegularFile(signedFile));
        CMSSignedData savedCms = new CMSSignedData(Files.readAllBytes(signedFile));
        assertNotNull(savedCms.getSignedContent());
        assertArrayEquals(Utils.readResource("arquivos/doc.txt"),
                (byte[]) savedCms.getSignedContent().getContent());
        SignerInformation signer = singleSigner(savedCms);
        assertEquals(NISTObjectIdentifiers.id_sha512.getId(), signer.getDigestAlgOID());
        assertTrue(PKCSObjectIdentifiers.rsaEncryption.getId().equals(signer.getEncryptionAlgOID())
                || PKCSObjectIdentifiers.sha512WithRSAEncryption.getId().equals(signer.getEncryptionAlgOID()));
        assertTrue(signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(new BouncyCastleProvider()).build(expectedCertificate.getPublicKey())));
    }

    @BeforeAll
    static void loadChallengeFixtures() throws Exception {
        pkcs12 = Utils.readResource("pkcs12/certificado_teste_hub.pfx");
        document = Utils.readResource("arquivos/doc.txt");
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new ByteArrayInputStream(pkcs12), PASSWORD.toCharArray());
        assertEquals(1, store.size(), "Expected a single entry in the supplied PKCS12");
        alias = store.aliases().nextElement();
        expectedCertificate = (X509Certificate) store.getCertificate(alias);
        assertNotNull(expectedCertificate, "Expected a certificate in the test PKCS12");
        assertTrue(store.isKeyEntry(alias), "Expected a private key in the fixture");
    }

    @ParameterizedTest(name = "CMS attached: {0}")
    @MethodSource("documents")
    void encapsulatesOriginalDocumentBytes(String scenario, byte[] content) throws Exception {
        CMSSignedData cms = sign(content);

        assertNotNull(cms.getSignedContent(), "Expected attached CMS with embedded content");
        assertArrayEquals(content, (byte[]) cms.getSignedContent().getContent(), scenario);
    }

    private static Stream<Arguments> documents() throws IOException {
        return Stream.of(
                Arguments.of("challenge doc.txt", Utils.readResource("arquivos/doc.txt")),
                Arguments.of("non-UTF-8 binary bytes", new byte[]{0, (byte) 0xff, 13, 10, (byte) 0x80}),
                Arguments.of("empty document", new byte[0])
        );
    }

    @Test
    void usesSha512WithRsa() throws Exception {
        SignerInformation signer = singleSigner(sign(document));

        assertEquals(NISTObjectIdentifiers.id_sha512.getId(), signer.getDigestAlgOID());
        assertTrue(PKCSObjectIdentifiers.rsaEncryption.getId().equals(signer.getEncryptionAlgOID())
                        || PKCSObjectIdentifiers.sha512WithRSAEncryption.getId().equals(signer.getEncryptionAlgOID()),
                "Expected RSA with SHA-512");
    }

    @Test
    void includesMatchingPkcs12Certificate() throws Exception {
        CMSSignedData cms = sign(document);
        SignerInformation signer = singleSigner(cms);
        Collection<X509CertificateHolder> certificates = cms.getCertificates().getMatches(null).stream()
                .filter(certificate -> signer.getSID().match(certificate)).toList();

        assertEquals(1, certificates.size(), "Expected one matching signer certificate");
        assertArrayEquals(expectedCertificate.getEncoded(), certificates.iterator().next().getEncoded());
    }

    @Test
    void verifiesWithExpectedPublicKey() throws Exception {
        SignerInformation signer = singleSigner(sign(document));

        assertTrue(signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(new BouncyCastleProvider())
                .build(expectedCertificate.getPublicKey())));
    }

    @Test
    void includesOriginalDocumentSha512Digest() throws Exception {
        SignerInformation signer = singleSigner(sign(document));
        assertNotNull(signer.getSignedAttributes());
        Attribute attribute = signer.getSignedAttributes().get(CMSAttributes.messageDigest);
        assertNotNull(attribute, "Expected a signed messageDigest attribute");
        byte[] digest = ASN1OctetString.getInstance(attribute.getAttrValues().getObjectAt(0)).getOctets();

        assertArrayEquals(MessageDigest.getInstance("SHA-512").digest(document), digest);
    }

    @Test
    void includesSigningTime() throws Exception {
        SignerInformation signer = singleSigner(sign(document));
        assertNotNull(signer.getSignedAttributes());
        Attribute attribute = signer.getSignedAttributes().get(CMSAttributes.signingTime);
        assertNotNull(attribute, "Stage 4 requires a signingTime attribute");
        assertEquals(1, attribute.getAttrValues().size());
        assertNotNull(Time.getInstance(attribute.getAttrValues().getObjectAt(0)).getDate());
    }

    @Test
    void rejectsIncorrectPassword() {
        assertThrows(IOException.class,
                () -> service.sign(document, pkcs12, alias, "incorrect-password".toCharArray()));
    }

    @Test
    void rejectsMalformedPkcs12() {
        assertThrows(IOException.class,
                () -> service.sign(document, new byte[]{1, 2, 3, 4}, alias, PASSWORD.toCharArray()));
    }

    @Test
    void rejectsUnknownAlias() {
        assertThrows(GeneralSecurityException.class,
                () -> service.sign(document, pkcs12, "missing-alias", PASSWORD.toCharArray()));
    }

    @Test
    void rejectsPkcs12WithoutPrivateKey() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, PASSWORD.toCharArray());
        store.setCertificateEntry("certificate-only", expectedCertificate);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        store.store(output, PASSWORD.toCharArray());

        assertThrows(GeneralSecurityException.class,
                () -> service.sign(document, output.toByteArray(), "certificate-only", PASSWORD.toCharArray()));
    }

    @Test
    void rejectsSecretKeyInsteadOfPrivateKey() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, PASSWORD.toCharArray());
        store.setEntry("secret-key", new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[16], "AES")),
                new KeyStore.PasswordProtection(PASSWORD.toCharArray()));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        store.store(output, PASSWORD.toCharArray());

        assertThrows(InvalidKeyException.class,
                () -> service.sign(document, output.toByteArray(), "secret-key", PASSWORD.toCharArray()));
    }

    @Test
    void preservesCauseWhenPrivateKeyPasswordIsIncorrect() throws Exception {
        KeyStore original = KeyStore.getInstance("PKCS12");
        original.load(new ByteArrayInputStream(pkcs12), PASSWORD.toCharArray());
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, PASSWORD.toCharArray());
        store.setKeyEntry(alias, original.getKey(alias, PASSWORD.toCharArray()),
                "different-key-password".toCharArray(), original.getCertificateChain(alias));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        store.store(output, PASSWORD.toCharArray());

        UnrecoverableKeyException error = assertThrows(UnrecoverableKeyException.class,
                () -> service.sign(document, output.toByteArray(), alias, PASSWORD.toCharArray()));
        assertInstanceOf(UnrecoverableKeyException.class, error.getCause());
        assertTrue(error.getMessage().contains(alias));
    }

    @ParameterizedTest(name = "Rejects null argument: {0}")
    @MethodSource("nullArguments")
    void rejectsNullArguments(String scenario, byte[] content, byte[] pkcs12Bytes, String keyAlias, char[] password) {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> service.sign(content, pkcs12Bytes, keyAlias, password), scenario);
        assertEquals(scenario + " must not be null", error.getMessage());
    }

    private static Stream<Arguments> nullArguments() {
        return Stream.of(
                Arguments.of("document", null, pkcs12, alias, PASSWORD.toCharArray()),
                Arguments.of("pkcs12", document, null, alias, PASSWORD.toCharArray()),
                Arguments.of("alias", document, pkcs12, null, PASSWORD.toCharArray()),
                Arguments.of("password", document, pkcs12, alias, null)
        );
    }

    private CMSSignedData sign(byte[] content) throws Exception {
        byte[] result = service.sign(content, pkcs12, alias, PASSWORD.toCharArray());
        assertNotNull(result, "Expected CMS bytes");
        assertTrue(result.length > 0, "CMS must not be empty");
        return new CMSSignedData(result);
    }

    private static SignerInformation singleSigner(CMSSignedData cms) {
        Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
        assertEquals(1, signers.size(), "Expected exactly one signer");
        return signers.iterator().next();
    }
}
