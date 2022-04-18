package you.shall.not.pass.filter;

import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import you.shall.not.pass.domain.Access;
import you.shall.not.pass.domain.Session;
import you.shall.not.pass.dto.Violation;
import you.shall.not.pass.exception.AccessGrantException;
import you.shall.not.pass.exception.CsrfViolationException;
import you.shall.not.pass.filter.staticresource.StaticResourceValidator;
import you.shall.not.pass.service.CookieService;
import you.shall.not.pass.service.CsrfProtectionService;
import you.shall.not.pass.service.SessionService;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Optional;

@Component
@Order(1)
public class GrantSecurityFilter implements Filter {

	public static final String SESSION_COOKIE_NAME = "GRANT";
	public static final String EXECUTE_FILTER_ONCE = "you.shall.not.pass.filter";

	private static final Logger LOG = LoggerFactory.getLogger(GrantSecurityFilter.class);

	private final Gson gson;
	private final CookieService cookieService;
	private final SessionService sessionService;
	private final List<StaticResourceValidator> resourcesValidators;
	private final CsrfProtectionService csrfProtectionService;

	@Value("${session.expiry.seconds}")
	private int sessionExpirySeconds;

	@Autowired
	public GrantSecurityFilter(Gson gson, CookieService cookieService, SessionService sessionService, List<StaticResourceValidator> resourcesValidators, CsrfProtectionService csrfProtectionService) {
		this.gson = gson;
		this.cookieService = cookieService;
		this.sessionService = sessionService;
		this.resourcesValidators = resourcesValidators;
		this.csrfProtectionService = csrfProtectionService;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		try {
			if (request.getAttribute(EXECUTE_FILTER_ONCE) == null) {
				shallNotPassLogic((HttpServletRequest) request, (HttpServletResponse)response);
			}
			request.setAttribute(EXECUTE_FILTER_ONCE, true);
			chain.doFilter(request, response);
		} catch (AccessGrantException age) {
			LOG.warn("Access violation, {}", age.getMessage());
			processAccessGrantError((HttpServletResponse) response, age);
		} catch (CsrfViolationException cve) {
			LOG.warn("CSRF violation, {}", cve.getMessage());
			processCsrfViolation((HttpServletResponse) response, cve);
		}
	}

	private void processCsrfViolation(HttpServletResponse response, CsrfViolationException cve) {
		Violation violation = Violation.builder()
				.message(cve.getMessage())
				.csrfPassed(false)
				.build();

		response.setStatus(HttpStatus.BAD_REQUEST.value());
		writeResponse(response, gson.toJson(violation));
	}

	private void processAccessGrantError(HttpServletResponse response, AccessGrantException age) {
		Violation violation = Violation.builder()
				.message(age.getMessage())
				.requiredAccess(age.getRequired())
				.build();

		response.setStatus(HttpStatus.FORBIDDEN.value());
		writeResponse(response, gson.toJson(violation));
	}

	private void shallNotPassLogic(HttpServletRequest request, HttpServletResponse response) {
		String sessionCookieValue = null;
		sessionCookieValue = cookieService.getCookieValue(request, SESSION_COOKIE_NAME);
		sessionCookieValue = handleAnonymousSession(request, response, sessionCookieValue);

		final Optional<Session> sessionByToken = sessionService.findSessionByToken(sessionCookieValue);
		final String requestedUri = request.getRequestURI();

		LOG.info("incoming request {} with token {}", requestedUri, sessionCookieValue);
		final Access grant = sessionByToken.map(Session::getGrant).orElse(null);
		LOG.info("user grant level {}", grant);

		final Optional<StaticResourceValidator> resourceValidator = getValidator(requestedUri);

		resourceValidator.ifPresent(validator -> {
			LOG.info("resource validator enforced {}", validator.requires());

			if (sessionService.isExpiredSession(sessionByToken)
					|| validator.requires().isLevelHigherThanSessionAccessLevel(grant)) {
				throw new AccessGrantException(validator.requires(), "invalid access level");
			}
			csrfProtectionService.validateCsrfCookie(request);
		});
	}

	private String handleAnonymousSession(HttpServletRequest request, HttpServletResponse response, String sessionCookieValue) {
		if (StringUtils.isEmpty(sessionCookieValue)) {
			sessionCookieValue = csrfProtectionService.generateToken();
			LOG.info("incoming request with no session cookie value, creating anonymous session {}", sessionCookieValue);

			String anonymousSessionCookie = sessionService.createAnonymousSession(sessionCookieValue);
			cookieService.addCookie(anonymousSessionCookie, response);

			request.setAttribute(SESSION_COOKIE_NAME, sessionCookieValue);
		}
		return sessionCookieValue;
	}

	private Optional<StaticResourceValidator> getValidator(String requestedUri) {
		return resourcesValidators.stream().filter(staticResourceValidator
				-> staticResourceValidator.isApplicable(requestedUri)).findFirst();
	}

	private void writeResponse(HttpServletResponse response, String message) {
		try {
			PrintWriter out = response.getWriter();
			LOG.info("response message {}", message);
			out.print(message);
			out.flush();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
