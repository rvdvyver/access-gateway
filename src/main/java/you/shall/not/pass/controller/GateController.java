package you.shall.not.pass.controller;

import com.google.gson.Gson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import you.shall.not.pass.dto.StaticResources;
import you.shall.not.pass.dto.Success;
import you.shall.not.pass.filter.staticresource.StaticResourceService;
import you.shall.not.pass.service.CookieService;
import you.shall.not.pass.service.CsrfProtectionService;
import you.shall.not.pass.service.SessionService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

import static you.shall.not.pass.filter.GrantSecurityFilter.SESSION_COOKIE_NAME;

@Controller
public class GateController {

	private final SessionService sessionService;
	private final CsrfProtectionService csrfProtectionService;
	private final StaticResourceService resourceService;
	private final CookieService cookieService;
	private final Gson gson;

	@Autowired
	public GateController(SessionService sessionService, CsrfProtectionService csrfProtectionService, StaticResourceService resourceService, CookieService cookieService, Gson gson) {
		this.sessionService = sessionService;
		this.csrfProtectionService = csrfProtectionService;
		this.resourceService = resourceService;
		this.cookieService = cookieService;
		this.gson = gson;
	}

	@GetMapping({"/access"})
	public ResponseEntity<String> access(HttpServletRequest request, HttpServletResponse response) {
		Success.SuccessBuilder builder = Success.builder();
		String cookieValue = cookieService.getCookieValue(request, SessionService.SESSION_COOKIE);

		if (StringUtils.isEmpty(cookieValue)) {
			cookieValue = String.valueOf(request.getAttribute(SESSION_COOKIE_NAME));
		}

		Optional<String> optionalSession = sessionService.authenticatedSession(cookieValue);
		optionalSession.ifPresent(session -> {
			String csrf = csrfProtectionService.getCsrfCookie();
			cookieService.addCookie(csrf, response);
			cookieService.addCookie(session, response);
			builder.authenticated(true);
		});
		return ResponseEntity.ok(gson.toJson(builder.build()));
	}

	@GetMapping({"/resources"})
	public ResponseEntity<String> resources() {
		StaticResources resources = StaticResources.builder()
				.resources(resourceService.getAllStaticResources()).build();
		return ResponseEntity.ok(gson.toJson(resources));
	}

	@GetMapping({"/home"})
	public String hello() {
		return "any-app";
	}

}
