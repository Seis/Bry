package br.com.bry.challenge.controller;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

import br.com.bry.challenge.dto.VerificationResponse;
import br.com.bry.challenge.service.SignatureService;
import br.com.bry.challenge.service.VerificationService;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class SignatureController {
    private final SignatureService signatureService;
    private final VerificationService verificationService;

    public SignatureController(SignatureService signatureService, VerificationService verificationService) {
        this.signatureService = signatureService;
        this.verificationService = verificationService;
    }

    @PostMapping(path = {"/signature/", "/signature"}, consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.TEXT_PLAIN_VALUE)
    public String sign(@RequestParam("document") MultipartFile document,
                       @RequestParam("pkcs12") MultipartFile pkcs12,
                       @RequestParam("password") String password)
            throws IOException, GeneralSecurityException, CMSException, OperatorCreationException {
        checkSize(document, 5 * 1024 * 1024);
        checkSize(pkcs12, 1024 * 1024);
        if (pkcs12.isEmpty()) {
            throw new IllegalArgumentException("pkcs12 must not be empty");
        }
        char[] keyPassword = password.toCharArray();
        try {
            return Base64.getEncoder().encodeToString(
                    signatureService.sign(document.getBytes(), pkcs12.getBytes(), keyPassword));
        } finally {
            Arrays.fill(keyPassword, '\0');
        }
    }

    @PostMapping(path = {"/verify/", "/verify"}, consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public VerificationResponse verify(@RequestParam("signature") MultipartFile signature)
            throws IOException, GeneralSecurityException, CMSException, OperatorCreationException {
        checkSize(signature, 10 * 1024 * 1024);
        if (signature.isEmpty()) {
            throw new IllegalArgumentException("signature must not be empty");
        }
        String encoded = new String(signature.getBytes(), StandardCharsets.US_ASCII)
                .replaceAll("[\\r\\n\\t ]", "");
        byte[] cms;
        try {
            cms = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("signature must contain valid Base64", e);
        }
        return VerificationResponse.from(verificationService.verify(cms));
    }

    private static void checkSize(MultipartFile file, long maxBytes) {
        if (file.getSize() > maxBytes) {
            throw new MaxUploadSizeExceededException(maxBytes);
        }
    }
}
