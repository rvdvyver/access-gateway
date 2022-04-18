package you.shall.not.pass.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Example;
import org.springframework.stereotype.Service;
import you.shall.not.pass.domain.Access;
import you.shall.not.pass.domain.Session;
import you.shall.not.pass.domain.User;
import you.shall.not.pass.repositories.SessionRepository;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.Optional;

@Service
public class SessionService {

    public static final String SESSION_COOKIE = "GRANT";

    private static final Logger LOG = LoggerFactory.getLogger(SessionService.class);

    private final SessionRepository sessionRepository;

    private final UserService userService;

    private final CsrfProtectionService csrfProtectionService;

    private final CookieService cookieService;

    private final DateService dateService;

    @Value("${session.expiry.seconds}")
    private int sessionExpirySeconds;

    public SessionService(SessionRepository sessionRepository, UserService userService, CsrfProtectionService csrfProtectionService, CookieService cookieService, DateService dateService) {
        this.sessionRepository = sessionRepository;
        this.userService = userService;
        this.csrfProtectionService = csrfProtectionService;
        this.cookieService = cookieService;
        this.dateService = dateService;
    }

    public Optional<Session> findSessionByToken(String token) {
        Example<Session> example = Example.of(Session.builder()
                .token(token).build());
        return sessionRepository.findOne(example);
    }

    public boolean isExpiredSession(Optional<Session> optionalSession) {
        return !optionalSession.isPresent() || optionalSession.filter(session -> LocalDateTime.now()
                .isAfter(dateService.asLocalDateTime(session.getDate()))).isPresent();
    }

    private Optional<Session> findLastKnownSession(User user, Access grant) {
        Example<Session> example = Example.of(Session.builder()
                .userId(user.getId()).grant(grant).build());
        return sessionRepository.findAll(example).stream()
                .sorted(Comparator.comparing(Session::getDate,
                Comparator.nullsLast(Comparator.reverseOrder()))).findFirst();
    }

    public Optional<String> authenticatedSession(String sessionCookieValue) {
        final String username = LogonUserService.getCurrentUser().orElseThrow(()
                -> new RuntimeException("unknown user requesting session!"));

        final Access level = LogonUserService.getCurrentAccessLevel().orElseThrow(()
                -> new RuntimeException("Invalid user access level!"));

        final User user = userService.getUserByName(username);
        Optional<Session> priorSession = findLastKnownSession(user, level);

        boolean expired = isExpiredSession(priorSession);
        if (!expired) {
            LOG.info("returning old session cookie");
            return createOldSessionCookie(priorSession);
        }

        LOG.info("returning new session cookie");
        return createNewSessionCookie(level, user, sessionCookieValue);
    }

    private Optional<String> createOldSessionCookie(Optional<Session> priorSession) {
        Session session = priorSession.orElseThrow(()
                -> new RuntimeException("This should never happen you may not pass!"));
        LocalDateTime cookieDate = dateService.asLocalDateTime(session.getDate());
        long diff = LocalDateTime.now().until(cookieDate, ChronoUnit.SECONDS);
        return Optional.of(createSessionCookie(session.getToken(), (int) diff));
    }

    private Optional<String> createNewSessionCookie(Access grant, User user, String token) {
        Session session = sessionRepository.findByToken(token);

        session.setDate(dateService.asDate(LocalDateTime.now().plusSeconds(sessionExpirySeconds)));
        session.setGrant(grant);
        session.setUserId(user.getId());

        sessionRepository.save(session);
        return Optional.of(createSessionCookie(token, sessionExpirySeconds));
    }

    public String createAnonymousSession(String token) {
        Session session = Session.builder()
                .date(dateService.asDate(LocalDateTime.now().plusSeconds(sessionExpirySeconds)))
                .grant(Access.Level0)
                .token(token)
                .build();

        sessionRepository.save(session);
        return cookieService.createCookie(SESSION_COOKIE, token, sessionExpirySeconds);
    }

    private String createSessionCookie(String token, int expireInSeconds) {
        return cookieService.createCookie(SESSION_COOKIE, token, expireInSeconds);
    }

}
