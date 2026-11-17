package br.com.bry.challenge.controller;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import br.com.bry.challenge.service.SignatureService;
import br.com.bry.challenge.service.VerificationService;
import br.com.bry.challenge.support.SigningMaterialFixtures;
import br.com.bry.challenge.util.Utils;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class SignatureControllerTest {
    private static byte[] document;
    private static byte[] pkcs12;
    private static byte[] cms;
    private static String alias;
    @Autowired private MockMvc mvc;
    @Autowired private VerificationService verificationService;

    @TestConfiguration
    static class FixedTime {
        @Bean @Primary
        Clock testClock() {
            return Clock.fixed(Instant.parse("2026-06-01T12:00:00Z"), ZoneOffset.UTC);
        }
    }

    @BeforeAll
    static void fixtures() throws Exception {
        document = Utils.readResource("arquivos/doc.txt");
        pkcs12 = Utils.readResource("pkcs12/certificado_teste_hub.pfx");
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new ByteArrayInputStream(pkcs12), "bry123456".toCharArray());
        alias = store.aliases().nextElement();
        cms = new SignatureService().sign(document, pkcs12, alias, "bry123456".toCharArray());
    }

    @Test
    void signsAndVerifiesUploadedDocumentEndToEnd() throws Exception {
        String encoded = mvc.perform(multipart("/signature/").file(file("document", document))
                        .file(file("pkcs12", pkcs12)).param("password", "bry123456"))
                .andExpect(status().isOk()).andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_PLAIN))
                .andReturn().getResponse().getContentAsString();
        assertArrayEquals(document, (byte[]) new CMSSignedData(Base64.getDecoder().decode(encoded))
                .getSignedContent().getContent());
        mvc.perform(multipart("/verify/").file(file("signature", encoded.getBytes(StandardCharsets.US_ASCII))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("VALIDO"))
                .andExpect(jsonPath("$.checks.integrityValid").value(true))
                .andExpect(jsonPath("$.checks.chainTrusted").value(true))
                .andExpect(jsonPath("$.checks.certificateTrusted").value(true))
                .andExpect(jsonPath("$.infos.signerName").value("HUB2 TESTES"))
                .andExpect(jsonPath("$.infos.documentHash").value("dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b045884fe72111b27cf7d6302916b2691ac7696c1637e1ab44584d8d6613825149e35"))
                .andExpect(jsonPath("$.infos.hashAlgorithm").value("SHA-512"))
                .andExpect(jsonPath("$.infos.signingTime").isString())
                .andExpect(jsonPath("$.observations").isArray());
    }

    @Test
    void acceptsBase64WithLineBreaksAndPathsWithoutTrailingSlash() throws Exception {
        mvc.perform(multipart("/verify").file(file("signature", Base64.getMimeEncoder().encode(cms))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("VALIDO"));
    }

    @Test
    void returnsInvalidForTamperedDocument() throws Exception {
        SignedData original = SignedData.getInstance(new CMSSignedData(cms).toASN1Structure().getContent());
        SignedData modified = new SignedData(original.getDigestAlgorithms(),
                new ContentInfo(CMSObjectIdentifiers.data, new DEROctetString(new byte[]{1, 2, 3})),
                original.getCertificates(), original.getCRLs(), original.getSignerInfos());
        byte[] encoded = Base64.getEncoder().encode(new ContentInfo(CMSObjectIdentifiers.signedData, modified).getEncoded());
        mvc.perform(multipart("/verify/").file(file("signature", encoded)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("INVALIDO"))
                .andExpect(jsonPath("$.checks.integrityValid").value(false))
                .andExpect(jsonPath("$.observations", hasItem(containsString("integrity"))));
    }

    @Test
    void returnsFutureSigningTimeWarningWithoutChangingValidStatus() throws Exception {
        mvc.perform(multipart("/verify/").file(file("signature", Base64.getEncoder().encode(cms))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("VALIDO"))
                .andExpect(jsonPath("$.checks.signingTimeInFuture").value(true))
                .andExpect(jsonPath("$.observations", hasItem(containsString("future"))));
    }

    @Test
    void expiredCertificateProducesWarningButStatusRemainsValid() throws Exception {
        var factory = java.security.cert.CertificateFactory.getInstance("X.509");
        var root = (java.security.cert.X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(Utils.readResource("cadeia/ac_raiz_bry_v3.cer")));
        var intermediate = (java.security.cert.X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(Utils.readResource("cadeia/ac_bry_servidor_seguro_v3.cer")));
        var verifier = new VerificationService(root, java.util.List.of(intermediate),
                Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC));
        MockMvc isolated = MockMvcBuilders.standaloneSetup(new SignatureController(new SignatureService(), verifier))
                .setControllerAdvice(new ApiExceptionHandler()).build();
        isolated.perform(multipart("/verify/").file(file("signature", Base64.getEncoder().encode(cms))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("VALIDO"))
                .andExpect(jsonPath("$.checks.chainTrusted").value(true))
                .andExpect(jsonPath("$.checks.certificateTrusted").value(false))
                .andExpect(jsonPath("$.checks.certificateExpired").value(true))
                .andExpect(jsonPath("$.observations", hasItem(containsString("expired"))));
    }

    @Test
    void cryptographicallyValidButUntrustedSignatureHasInvalidStatus() throws Exception {
        var keys = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        var name = new org.bouncycastle.asn1.x500.X500Name("CN=Untrusted");
        var certificate = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider(provider)
                .getCertificate(new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(name,
                        java.math.BigInteger.ONE, java.util.Date.from(Instant.parse("2020-01-01T00:00:00Z")),
                        java.util.Date.from(Instant.parse("2040-01-01T00:00:00Z")), name, keys.getPublic())
                        .build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA512withRSA")
                                .setProvider(provider).build(keys.getPrivate())));
        var generator = new org.bouncycastle.cms.CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder()
                .setProvider(provider).build("SHA512withRSA", keys.getPrivate(), certificate));
        generator.addCertificates(new org.bouncycastle.cert.jcajce.JcaCertStore(java.util.List.of(certificate)));
        byte[] encoded = Base64.getEncoder().encode(generator.generate(
                new org.bouncycastle.cms.CMSProcessableByteArray(document), true).getEncoded());
        mvc.perform(multipart("/verify/").file(file("signature", encoded)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("INVALIDO"))
                .andExpect(jsonPath("$.checks.integrityValid").value(true))
                .andExpect(jsonPath("$.checks.chainTrusted").value(false))
                .andExpect(jsonPath("$.observations", hasItem(containsString("trusted root"))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"document", "pkcs12", "password"})
    void rejectsMissingSigningParameter(String missing) throws Exception {
        var request = multipart("/signature/");
        if (!missing.equals("document")) request.file(file("document", document));
        if (!missing.equals("pkcs12")) request.file(file("pkcs12", pkcs12));
        if (!missing.equals("password")) request.param("password", "bry123456");
        mvc.perform(request).andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));
    }

    @Test
    void rejectsIncorrectPasswordWithoutExposingIt() throws Exception {
        mvc.perform(multipart("/signature/").file(file("document", document)).file(file("pkcs12", pkcs12))
                        .param("password", "secret-wrong-password"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(not(containsString("secret-wrong-password"))));
    }

    @Test
    void rejectsInvalidPkcs12() throws Exception {
        mvc.perform(multipart("/signature/").file(file("document", document))
                        .file(file("pkcs12", new byte[]{1, 2, 3})).param("password", "bry123456"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsMismatchedPrivateKeyAndCertificate() throws Exception {
        byte[] mismatched = SigningMaterialFixtures.withMismatchedCertificate(pkcs12, alias,
                "bry123456".toCharArray());

        mvc.perform(multipart("/signature/").file(file("document", document))
                        .file(file("pkcs12", mismatched)).param("password", "bry123456"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON));
    }

    @Test
    void signsWithRsaKeyDespiteDifferentlyProtectedSecretKey() throws Exception {
        byte[] mixed = SigningMaterialFixtures.withDifferentlyProtectedSecretKey(pkcs12,
                "bry123456".toCharArray());

        String encoded = mvc.perform(multipart("/signature/").file(file("document", document))
                        .file(file("pkcs12", mixed)).param("password", "bry123456"))
                .andExpect(status().isOk()).andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_PLAIN))
                .andReturn().getResponse().getContentAsString();

        byte[] cms = Base64.getDecoder().decode(encoded);
        assertArrayEquals(document, (byte[]) new CMSSignedData(cms).getSignedContent().getContent());
        assertTrue(verificationService.verify(cms).checks().integrityValid());
    }

    @Test
    void rejectsEmptyPkcs12() throws Exception {
        mvc.perform(multipart("/signature/").file(file("document", document))
                        .file(file("pkcs12", new byte[0])).param("password", "bry123456"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void signsAnEmptyDocument() throws Exception {
        mvc.perform(multipart("/signature/").file(file("document", new byte[0]))
                        .file(file("pkcs12", pkcs12)).param("password", "bry123456"))
                .andExpect(status().isOk());
    }

    @Test
    void rejectsAmbiguousPrivateKeys() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new ByteArrayInputStream(pkcs12), "bry123456".toCharArray());
        store.setKeyEntry("second-key", store.getKey(alias, "bry123456".toCharArray()),
                "bry123456".toCharArray(), store.getCertificateChain(alias));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        store.store(output, "bry123456".toCharArray());
        mvc.perform(multipart("/signature/").file(file("document", document))
                        .file(file("pkcs12", output.toByteArray())).param("password", "bry123456"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsDocumentAboveLimit() throws Exception {
        mvc.perform(multipart("/signature/").file(file("document", new byte[5 * 1024 * 1024 + 1]))
                        .file(file("pkcs12", pkcs12)).param("password", "bry123456"))
                .andExpect(status().isPayloadTooLarge());
    }

    @Test
    void rejectsMissingSignature() throws Exception {
        mvc.perform(multipart("/verify/")).andExpect(status().isBadRequest());
    }

    @Test
    void rejectsEmptySignature() throws Exception {
        mvc.perform(multipart("/verify/").file(file("signature", new byte[0])))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsInvalidBase64() throws Exception {
        mvc.perform(multipart("/verify/").file(file("signature", "not!base64".getBytes(StandardCharsets.US_ASCII))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsValidBase64ThatIsNotCms() throws Exception {
        mvc.perform(multipart("/verify/").file(file("signature", Base64.getEncoder().encode(new byte[]{1, 2, 3}))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsUnsupportedMediaType() throws Exception {
        mvc.perform(post("/signature/").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnsupportedMediaType());
    }

    @Test
    void unexpectedErrorsHaveGenericResponses() throws Exception {
        SignatureService failingService = new SignatureService() {
            @Override
            public byte[] sign(byte[] document, byte[] pkcs12, char[] password) throws IOException {
                throw new IOException("internal-sensitive-detail");
            }
        };
        MockMvc isolated = MockMvcBuilders.standaloneSetup(new SignatureController(failingService, verificationService))
                .setControllerAdvice(new ApiExceptionHandler()).build();
        isolated.perform(multipart("/signature/").file(file("document", document))
                        .file(file("pkcs12", pkcs12)).param("password", "bry123456"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.detail").value("Unable to process request"))
                .andExpect(content().string(not(containsString("internal-sensitive-detail"))));
    }

    private static MockMultipartFile file(String name, byte[] bytes) {
        return new MockMultipartFile(name, name + ".bin", MediaType.APPLICATION_OCTET_STREAM_VALUE, bytes);
    }
}
