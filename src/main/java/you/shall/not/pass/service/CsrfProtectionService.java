package you.shall.not.pass.service;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import you.shall.not.pass.exception.CsrfViolationException;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


@Service
public class CsrfProtectionService {

    private static final Logger LOG = LoggerFactory.getLogger(CsrfProtectionService.class);

    private final static String CSRF_COOKIE_NAME = "CSRF";
    private final static String XSRF_GUARD_NAME = "XSRF";

    private final static int CSRF_TOKEN_SIZE = 8;
    private final static Pattern GUARD_PATTERN = Pattern.compile("[a-zA-Z0-9]{16}_[0-9]{10}");

    @Value("${csrf.expiry.seconds}")
    private int expiry;

    private CookieService cookieService;
    private SecureTokenService tokenService;

    public CsrfProtectionService(CookieService cookieService, SecureTokenService tokenService) {
        this.cookieService = cookieService;
        this.tokenService = tokenService;
    }

    public String getCsrfCookie() {
        long epoch = OffsetDateTime.now().plusSeconds(expiry).toEpochSecond();
        final String token = tokenService.generateToken(CSRF_TOKEN_SIZE) + "_" + epoch;
        return cookieService.createCookie(CSRF_COOKIE_NAME, token, expiry);
    }

    public void validateCsrfCookie(HttpServletRequest request) {
        final String xsrfGuard = getCsrfGuardCheckValue(request);
        final String csrf = cookieService.getCookieValue(request, CSRF_COOKIE_NAME);

        LOG.info("incoming csrf cookie: {}", csrf);
        LOG.info("incoming xsrf value: {}", xsrfGuard);

        if (csrf == null && xsrfGuard == null) {
            throw new CsrfViolationException("Either the CSRF Token or the XSRF token is missing.");
        }

        final Matcher matcher = GUARD_PATTERN.matcher(csrf);
        boolean matches = matcher.matches();

        LOG.info("csrf cookie pattern guard passed: {}", matches);

        if (!matches) {
            throw new CsrfViolationException("CSRF Token is not valid.");
        }

        long diff = getEpochSecondsDiff(csrf);

        LOG.info("csrf cookie expiry in {} secs", diff);

        if (!csrf.equals(xsrfGuard)) {
            throw new CsrfViolationException("CSRF/XSRF failed validation.");
        } else if (diff <= 0) {
            throw new CsrfViolationException("CSRF token expired.");
        }
    }

    private String getCsrfGuardCheckValue(HttpServletRequest request) {
        String guardCheckValue = request.getHeader(XSRF_GUARD_NAME);
        if (guardCheckValue == null) {
            guardCheckValue = request.getParameter(XSRF_GUARD_NAME);
        }
        return guardCheckValue;
    }

    private long getEpochSecondsDiff(String cookieValue) {
        final String values[] = cookieValue.split("_");
        final String epochReceived = values[1];
        final Instant ofEpochSecond = Instant.ofEpochSecond(Long.parseLong(epochReceived));
        final OffsetDateTime ofInstant = OffsetDateTime.ofInstant(ofEpochSecond, ZoneId.systemDefault());
        return OffsetDateTime.now().until(ofInstant, ChronoUnit.SECONDS);
    }
}
