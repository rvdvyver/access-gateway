package you.shall.not.pass.controller;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import you.shall.not.pass.filter.GrantSecurityFilter;

import javax.servlet.http.Cookie;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class GateControllerTest {

	private final static String CSRF_COOKIE_NAME = "CSRF";
	private final static String XSRF_GUARD_NAME = "XSRF";
	private static final String GRANT_COOKIE_NAME = "GRANT";

	@Autowired
	MockMvc mvc;

	@Autowired
	private GrantSecurityFilter grantSecurityFilter;

	@Autowired
	private WebApplicationContext context;

	@Before
	public void setup() {
		mvc = MockMvcBuilders
				.webAppContextSetup(context)
				.apply(springSecurity())
				.addFilter(grantSecurityFilter)
				.build();
	}

	@Test
	public void shouldLogin() throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/access")
				.with(httpBasic("1#bob", "12341")))
				.andExpect(status().isOk())
				.andExpect(content().json("{'authenticated':true}"));
	}

	@Test
	public void shouldFailLogin() throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/access")
				.with(httpBasic("1#bob", "1")))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void shouldFailLoginToIncorrectDomain() throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/access")
				.with(httpBasic("2#bob", "12341")))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void shouldLoginAndResponseHasGrantCookie() throws Exception {
		MockHttpServletResponse response = loginWithUser("1#bob", "12341");

		Cookie grantCookie = response.getCookie(GRANT_COOKIE_NAME);
		assertNotNull(grantCookie);
		assertTrue(grantCookie.getValue().length() >= 0);
	}

	@Test
	public void shouldLoginAndResponseHasCsrfCookie() throws Exception {
		MockHttpServletResponse response = loginWithUser("1#bob", "12341");
		Cookie cookie = response.getCookie(CSRF_COOKIE_NAME);
		assertTrue(cookie.getValue().length() >= 0);
	}

	@Test
	public void shouldAccessResources() throws Exception {
		MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/resources"))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(status().isOk())
				.andReturn();

		String contentAsString = mvcResult.getResponse().getContentAsString();
		assertTrue(contentAsString.contains("/Level1/low/access.html"));
	}

	@Test
	public void shouldAccessLevel1Resources() throws Exception {
		MockHttpServletResponse response = loginWithUser("1#bob", "12341");

		Cookie csrfCookie = response.getCookie(CSRF_COOKIE_NAME);
		Cookie grantCookie = response.getCookie(GRANT_COOKIE_NAME);

		MvcResult levelOneRequestResponse = mvc.perform(MockMvcRequestBuilders.get("/Level1/low/access.html")
				.header(XSRF_GUARD_NAME, csrfCookie.getValue())
				.cookie(csrfCookie, grantCookie))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(status().isOk())
				.andReturn();

		String contentAsString = levelOneRequestResponse.getResponse().getContentAsString();
		assertTrue(contentAsString.contains("<h2>Sponge bob</h2>"));
	}

	@Test
	public void shouldNotAccessLevel2Resources() throws Exception {
		MockHttpServletResponse response = loginWithUser("1#bob", "12341");

		Cookie csrfCookie = response.getCookie(CSRF_COOKIE_NAME);
		Cookie grantCookie = response.getCookie(GRANT_COOKIE_NAME);

		mvc.perform(MockMvcRequestBuilders.get("/Level2/high_access.html")
				.header(XSRF_GUARD_NAME, csrfCookie.getValue())
				.cookie(csrfCookie, grantCookie))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(status().isForbidden());
	}

	private MockHttpServletResponse loginWithUser(String username, String password) throws Exception {
		MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/access")
				.with(httpBasic(username, password)))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(status().isOk())
				.andReturn();

		return mvcResult.getResponse();
	}
}
