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
import org.springframework.test.web.servlet.ResultMatcher;
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
	public void shouldLoginWithValidCredentialsAndDomain() throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/access")
				.with(httpBasic("1#bob", "12341")))
				.andExpect(status().isOk())
				.andExpect(content().json("{'authenticated':true}"));
	}

	@Test
	public void shouldReturnGrantCookieWithAnyRequest() throws Exception {
		Cookie cookie = mvc.perform(MockMvcRequestBuilders.get("/home"))
				.andExpect(status().isOk())
				.andReturn()
				.getResponse()
				.getCookie(GRANT_COOKIE_NAME);

		assertNotNull(cookie);
		assertNotNull(cookie.getValue());
	}

	@Test
	public void shouldFailLoginWithWrongPassword() throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/access")
				.with(httpBasic("1#bob", "wrongPassword")))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void shouldFailLoginWithValidCredentialsToIncorrectDomain() throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/access")
				.with(httpBasic("2#bob", "12341")))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void shouldLoginAndResponseHasGrantCookie() throws Exception {
		MockHttpServletResponse response = loginWithUserWithExpectedStatus("1#bob", "12341", status().isOk());

		Cookie grantCookie = response.getCookie(GRANT_COOKIE_NAME);
		assertNotNull(grantCookie);
		assertTrue(grantCookie.getValue().length() >= 0);
	}

	@Test
	public void shouldLoginAndResponseHasCsrfCookie() throws Exception {
		MockHttpServletResponse response = loginWithUserWithExpectedStatus("1#bob", "12341", status().isOk());
		Cookie cookie = response.getCookie(CSRF_COOKIE_NAME);
		assertTrue(cookie.getValue().length() >= 0);
	}

	@Test
	public void shouldAccessResourcesPage() throws Exception {
		MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/resources"))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(status().isOk())
				.andReturn();

		String contentAsString = mvcResult.getResponse().getContentAsString();
		assertTrue(contentAsString.contains("/Level1/low/access.html"));
	}

	@Test
	public void shouldAccessLevel1Resources() throws Exception {
		MockHttpServletResponse response = loginWithUserWithExpectedStatus("1#bob", "12341", status().isOk());

		Cookie csrfCookie = response.getCookie(CSRF_COOKIE_NAME);
		Cookie grantCookie = response.getCookie(GRANT_COOKIE_NAME);

		MvcResult levelOneRequestResponse = requestResourceAt(csrfCookie, grantCookie, "/Level1/low/access.html", status().isOk());

		String contentAsString = levelOneRequestResponse.getResponse().getContentAsString();
		assertTrue(contentAsString.contains("<h2>Sponge bob</h2>"));
	}

	@Test
	public void shouldNotAccessLevel2Resources() throws Exception {
		MockHttpServletResponse response = loginWithUserWithExpectedStatus("1#bob", "12341", status().isOk());

		Cookie csrfCookie = response.getCookie(CSRF_COOKIE_NAME);
		Cookie grantCookie = response.getCookie(GRANT_COOKIE_NAME);

		mvc.perform(MockMvcRequestBuilders.get("/Level2/high_access.html")
				.header(XSRF_GUARD_NAME, csrfCookie.getValue())
				.cookie(csrfCookie, grantCookie))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(status().isForbidden());
	}

	private MvcResult requestResourceAt(Cookie csrfCookie, Cookie grantCookie, String urlTemplate, ResultMatcher status) throws Exception {
		MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get(urlTemplate)
				.header(XSRF_GUARD_NAME, csrfCookie.getValue())
				.cookie(csrfCookie, grantCookie))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(status)
				.andReturn();
		return mvcResult;
	}

	private MockHttpServletResponse loginWithUserWithExpectedStatus(String username, String password, ResultMatcher expectedStatus) throws Exception {
		MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/access")
				.with(httpBasic(username, password)))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(expectedStatus)
				.andReturn();

		return mvcResult.getResponse();
	}
}
