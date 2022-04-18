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

	private static final String CSRF_COOKIE_NAME = "CSRF";
	private static final String XSRF_GUARD_NAME = "XSRF";
	private static final String GRANT_COOKIE_NAME = "GRANT";
	private static final String PUBLIC_RESOURCE_PATH = "/css/main.css";
	private static final String LEVEL_1_RESOURCE_PATH = "/Level1/low/access.html";
	private static final String LEVEL_2_RESOURCE_PATH = "/Level2/what/am/I/access.html";
	private static final String VALID_LEVEL1_PASSWORD = "12341";
	private static final String LEVEL_1_USERNAME = "1#bob";
	private static final String LEVEL_2_USERNAME = "2#bob";

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
				.with(httpBasic(LEVEL_1_USERNAME, "wrongPassword")))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void shouldFailLoginWithValidCredentialsToIncorrectDomain() throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/access")
				.with(httpBasic(LEVEL_2_USERNAME, "12341")))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void shouldLoginAndResponseHasGrantCookie() throws Exception {
		MockHttpServletResponse response = loginWithLevel1User();

		Cookie grantCookie = response.getCookie(GRANT_COOKIE_NAME);
		assertNotNull(grantCookie);
		assertTrue(grantCookie.getValue().length() >= 0);
	}

	@Test
	public void shouldLoginAndResponseHasCsrfCookie() throws Exception {
		MockHttpServletResponse response = loginWithLevel1User();
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

		assertTrue(contentAsString.contains(LEVEL_1_RESOURCE_PATH));
		assertTrue(contentAsString.contains(LEVEL_2_RESOURCE_PATH));
	}

	@Test
	public void shouldAccessPublicResourceResourcesWhenLoggedIn() throws Exception {
		MockHttpServletResponse response = loginWithLevel1User();
		MvcResult levelOneRequestResponse = requestResourceFromAndExpectStatus(response, PUBLIC_RESOURCE_PATH, status().isOk());

		String contentAsString = levelOneRequestResponse.getResponse().getContentAsString();
		assertTrue(contentAsString.contains(".hello-title"));
	}

	@Test
	public void shouldAccessPublicResourceResourcesWithNoUser() throws Exception {
		MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get(PUBLIC_RESOURCE_PATH))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(status().isOk())
				.andReturn();

		String contentAsString = mvcResult.getResponse().getContentAsString();
		assertTrue(contentAsString.contains(".hello-title"));
	}

	@Test
	public void shouldAccessLevel1Resources() throws Exception {
		MockHttpServletResponse response = loginWithLevel1User();
		MvcResult levelOneRequestResponse = requestResourceFromAndExpectStatus(response, LEVEL_1_RESOURCE_PATH, status().isOk());

		String contentAsString = levelOneRequestResponse.getResponse().getContentAsString();
		assertTrue(contentAsString.contains("<h2>Sponge bob</h2>"));
	}

	@Test
	public void shouldAccessLevel2Resources() throws Exception {
		MockHttpServletResponse response = loginWithUserWithExpectedStatus("2#bob", "test1", status().isOk());
		MvcResult levelTwoRequestResponse = requestResourceFromAndExpectStatus(response, LEVEL_2_RESOURCE_PATH, status().isOk());

		String contentAsString = levelTwoRequestResponse.getResponse().getContentAsString();
		assertTrue(contentAsString.contains("<h2>Smooth Criminal</h2>"));
	}


	private MvcResult requestResourceFromAndExpectStatus(MockHttpServletResponse loginResponse, String urlTemplate, ResultMatcher status) throws Exception {
		Cookie csrfCookie = loginResponse.getCookie(CSRF_COOKIE_NAME);
		Cookie grantCookie = loginResponse.getCookie(GRANT_COOKIE_NAME);

		MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get(urlTemplate)
				.header(XSRF_GUARD_NAME, csrfCookie.getValue())
				.cookie(csrfCookie, grantCookie))
				.andDo(MockMvcResultHandlers.print())
				.andExpect(status)
				.andReturn();
		return mvcResult;
	}

	private MockHttpServletResponse loginWithLevel1User() throws Exception {
		return loginWithUserWithExpectedStatus(LEVEL_1_USERNAME, VALID_LEVEL1_PASSWORD, status().isOk());
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
