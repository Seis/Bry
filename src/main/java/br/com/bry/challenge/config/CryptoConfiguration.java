package br.com.bry.challenge.config;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.List;

import br.com.bry.challenge.service.SignatureService;
import br.com.bry.challenge.service.VerificationService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

@Configuration
public class CryptoConfiguration {
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public SignatureService signatureService() {
        return new SignatureService();
    }

    @Bean
    public VerificationService verificationService(Clock clock) throws IOException, CertificateException {
        return new VerificationService(readCertificate("cadeia/ac_raiz_bry_v3.cer"),
                List.of(readCertificate("cadeia/ac_bry_servidor_seguro_v3.cer")), clock);
    }

    private X509Certificate readCertificate(String path) throws IOException, CertificateException {
        try (InputStream input = new ClassPathResource(path).getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509", new BouncyCastleProvider())
                    .generateCertificate(input);
        }
    }
}
