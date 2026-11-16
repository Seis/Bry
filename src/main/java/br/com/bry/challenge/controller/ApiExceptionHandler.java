package br.com.bry.challenge.controller;

import br.com.bry.challenge.exception.InvalidSigningMaterialException;
import org.bouncycastle.cms.CMSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {
    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail invalidArgument(IllegalArgumentException exception) {
        log.warn("Request rejected: invalid argument");
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Invalid request parameters");
    }

    @ExceptionHandler(InvalidSigningMaterialException.class)
    public ProblemDetail invalidSigningMaterial(InvalidSigningMaterialException exception) {
        log.warn("Request rejected: invalid signing material");
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST,
                "Invalid PKCS12 or password; exactly one RSA private key with a certificate is required");
    }

    @ExceptionHandler(CMSException.class)
    public ProblemDetail invalidCms(CMSException exception) {
        log.warn("Request rejected: invalid or unsupported CMS");
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Invalid or unsupported CMS signature");
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail unexpectedError(Exception exception) {
        log.error("Unexpected request processing failure", exception);
        return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "Unable to process request");
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception exception, Object body, HttpHeaders headers,
                                                              HttpStatusCode status, WebRequest request) {
        log.warn("HTTP request rejected: status={}", status.value());
        return super.handleExceptionInternal(exception, body, headers, status, request);
    }
}
