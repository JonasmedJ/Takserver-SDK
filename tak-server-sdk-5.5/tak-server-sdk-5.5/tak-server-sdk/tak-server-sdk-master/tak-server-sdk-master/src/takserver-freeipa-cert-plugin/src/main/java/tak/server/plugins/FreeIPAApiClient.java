package tak.server.plugins;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Client for the FreeIPA JSON-RPC API.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Authenticate to FreeIPA as the plugin admin (session cookie management).</li>
 *   <li>Validate end-user credentials by attempting a user-level login.</li>
 *   <li>Submit a PKCS#10 CSR and retrieve the signed DER certificate.</li>
 *   <li>Fetch the FreeIPA CA certificate chain.</li>
 *   <li>Revoke a certificate by serial number.</li>
 * </ul>
 *
 * <p>The admin session is cached and automatically refreshed when it expires
 * (FreeIPA default session lifetime is 20 minutes).
 */
public class FreeIPAApiClient {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    /** FreeIPA session lifetime margin – refresh 2 minutes before expiry */
    private static final long SESSION_REFRESH_MARGIN_SECONDS = 120;
    /** FreeIPA default session duration */
    private static final long SESSION_LIFETIME_SECONDS = 20 * 60;

    private final FreeIPAConfig config;
    private final Gson gson = new Gson();

    // Admin session state (guarded by sessionLock)
    private final ReentrantLock sessionLock = new ReentrantLock();
    private volatile String adminSessionCookie = null;
    private volatile Instant adminSessionExpiry = Instant.EPOCH;

    private final CloseableHttpClient httpClient;

    public FreeIPAApiClient(FreeIPAConfig config) {
        this.config = config;
        this.httpClient = buildHttpClient();
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /**
     * Validate the supplied credentials against FreeIPA by attempting to log
     * in as that user.  Returns {@code true} if FreeIPA accepts them.
     */
    public boolean validateUserCredentials(String username, String password) {
        try {
            String cookie = doLogin(username, password);
            return cookie != null;
        } catch (Exception e) {
            logger.debug("Credential validation failed for user {}: {}", username, e.getMessage());
            return false;
        }
    }

    /**
     * Submit a PEM-encoded PKCS#10 CSR to FreeIPA and return the signed
     * certificate as a base64-encoded DER byte array.
     *
     * @param username  ATAK user name (becomes the Kerberos principal)
     * @param csrPem    PEM string beginning with -----BEGIN CERTIFICATE REQUEST-----
     * @return base64-encoded DER certificate bytes
     * @throws Exception if FreeIPA rejects the request or any I/O error occurs
     */
    public String requestCertificate(String username, String csrPem) throws Exception {
        ensureAdminSession();

        String principal = username + "@" + config.getFreeIpaRealm();

        // Build the cert_request JSON-RPC payload
        JsonObject params = new JsonObject();
        params.addProperty("principal", principal);
        params.addProperty("profile_id", config.getFreeIpaCertProfile());
        params.addProperty("cacn", config.getFreeIpaCaCn());
        params.addProperty("add", true);          // auto-add host/user if missing

        JsonArray positionalArgs = new JsonArray();
        positionalArgs.add(csrPem);

        JsonObject body = new JsonObject();
        body.addProperty("method", "cert_request");
        body.addProperty("id", 0);
        body.add("params", buildParams(positionalArgs, params));

        String responseBody = callApi(body.toString());
        JsonObject response = JsonParser.parseString(responseBody).getAsJsonObject();
        checkApiError(response, "cert_request");

        JsonObject result = response
                .getAsJsonObject("result")
                .getAsJsonObject("result");

        if (!result.has("certificate")) {
            throw new Exception("FreeIPA cert_request response missing 'certificate' field");
        }

        String certDerBase64 = result.get("certificate").getAsString()
                .replaceAll("\\s", "");  // strip any embedded whitespace

        long serial = result.has("serial_number")
                ? result.get("serial_number").getAsLong() : -1;
        logger.info("FreeIPA issued certificate serial={} for user={}", serial, username);

        return certDerBase64;
    }

    /**
     * Retrieve the FreeIPA CA certificate in PEM format.
     * Uses the unauthenticated {@code /ipa/config/ca.crt} endpoint.
     */
    public String getCaCertificatePem() throws Exception {
        String url = config.getFreeIpaUrl() + "/ipa/config/ca.crt";
        HttpGet get = new HttpGet(url);
        get.addHeader("Accept", "application/x-pem-file");

        try (CloseableHttpResponse resp = httpClient.execute(get)) {
            int status = resp.getCode();
            if (status != 200) {
                throw new Exception("Failed to fetch CA cert, HTTP " + status);
            }
            return EntityUtils.toString(resp.getEntity(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Revoke a certificate by its serial number.
     *
     * @param serialNumber decimal serial number
     * @param reason       RFC 5280 reason code (0 = unspecified, 1 = keyCompromise, etc.)
     */
    public void revokeCertificate(long serialNumber, int reason) throws Exception {
        ensureAdminSession();

        JsonObject params = new JsonObject();
        params.addProperty("reason", reason);

        JsonArray positionalArgs = new JsonArray();
        positionalArgs.add(serialNumber);

        JsonObject body = new JsonObject();
        body.addProperty("method", "cert_revoke");
        body.addProperty("id", 0);
        body.add("params", buildParams(positionalArgs, params));

        String responseBody = callApi(body.toString());
        JsonObject response = JsonParser.parseString(responseBody).getAsJsonObject();
        checkApiError(response, "cert_revoke");
        logger.info("Revoked certificate serial={} reason={}", serialNumber, reason);
    }

    /**
     * Look up a user in FreeIPA to verify the account exists and is active.
     * Returns {@code true} if the account exists and is not disabled.
     */
    public boolean userExists(String username) throws Exception {
        ensureAdminSession();

        JsonObject params = new JsonObject();
        params.addProperty("all", false);

        JsonArray positionalArgs = new JsonArray();
        positionalArgs.add(username);

        JsonObject body = new JsonObject();
        body.addProperty("method", "user_show");
        body.addProperty("id", 0);
        body.add("params", buildParams(positionalArgs, params));

        try {
            String responseBody = callApi(body.toString());
            JsonObject response = JsonParser.parseString(responseBody).getAsJsonObject();
            if (response.has("error") && !response.get("error").isJsonNull()) {
                return false;
            }
            // Check disabled flag
            JsonObject result = response.getAsJsonObject("result").getAsJsonObject("result");
            if (result.has("nsaccountlock")) {
                boolean locked = result.get("nsaccountlock").getAsBoolean();
                if (locked) {
                    logger.warn("User {} exists but account is locked in FreeIPA", username);
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            logger.debug("user_show failed for {}: {}", username, e.getMessage());
            return false;
        }
    }

    public void close() {
        try { httpClient.close(); } catch (IOException ignored) { }
    }

    // ── Session management ──────────────────────────────────────────────────

    private void ensureAdminSession() throws Exception {
        sessionLock.lock();
        try {
            if (adminSessionCookie == null ||
                    Instant.now().isAfter(adminSessionExpiry.minusSeconds(SESSION_REFRESH_MARGIN_SECONDS))) {
                logger.debug("Refreshing FreeIPA admin session");
                adminSessionCookie = doLogin(config.getFreeIpaAdminUser(), config.getFreeIpaAdminPassword());
                if (adminSessionCookie == null) {
                    throw new Exception("FreeIPA admin authentication failed – check freeIpaAdminUser/freeIpaAdminPassword");
                }
                adminSessionExpiry = Instant.now().plusSeconds(SESSION_LIFETIME_SECONDS);
                logger.info("FreeIPA admin session established, expires ~{}", adminSessionExpiry);
            }
        } finally {
            sessionLock.unlock();
        }
    }

    /**
     * Attempts login_password against FreeIPA.
     *
     * @return the {@code ipa_session} cookie value, or {@code null} on failure
     */
    private String doLogin(String user, String password) throws Exception {
        String loginUrl = config.getFreeIpaUrl() + "/ipa/session/login_password";

        HttpPost post = new HttpPost(loginUrl);
        post.addHeader("Content-Type", "application/x-www-form-urlencoded");
        post.addHeader("Accept", "text/plain");
        post.addHeader("Referer", config.getFreeIpaUrl() + "/ipa");

        List<NameValuePair> form = new ArrayList<>();
        form.add(new BasicNameValuePair("user", user));
        form.add(new BasicNameValuePair("password", password));
        post.setEntity(new UrlEncodedFormEntity(form, StandardCharsets.UTF_8));

        try (CloseableHttpResponse resp = httpClient.execute(post)) {
            int status = resp.getCode();
            if (status == 200) {
                // FreeIPA sets multiple Set-Cookie headers; ipa_session may not be the first.
                // Iterate all of them to find the ipa_session cookie value.
                for (org.apache.hc.core5.http.Header h : resp.getHeaders("Set-Cookie")) {
                    String headerValue = h.getValue();
                    if (headerValue != null && headerValue.contains("ipa_session=")) {
                        String sessionValue = headerValue.split("ipa_session=")[1].split(";")[0];
                        return "ipa_session=" + sessionValue;
                    }
                }
                logger.warn("Login returned 200 but no ipa_session cookie found for user {}", user);
                return null;
            } else if (status == 401) {
                return null; // invalid credentials
            } else {
                throw new Exception("Unexpected HTTP " + status + " from FreeIPA login for user " + user);
            }
        }
    }

    // ── HTTP helper ─────────────────────────────────────────────────────────

    private String callApi(String jsonBody) throws Exception {
        // Re-try once on 401 (session expired)
        for (int attempt = 0; attempt < 2; attempt++) {
            String cookie = adminSessionCookie;
            if (cookie == null) ensureAdminSession();
            cookie = adminSessionCookie;

            String result = doCallApi(jsonBody, cookie);
            if (result != null) return result;

            // Session likely expired, force refresh
            sessionLock.lock();
            try { adminSessionCookie = null; } finally { sessionLock.unlock(); }
            ensureAdminSession();
        }
        throw new Exception("Failed to call FreeIPA API after session refresh");
    }

    private String doCallApi(String jsonBody, String cookie) throws Exception {
        String apiUrl = config.getFreeIpaUrl() + "/ipa/session/json";

        HttpPost post = new HttpPost(apiUrl);
        post.addHeader("Content-Type", "application/json");
        post.addHeader("Accept", "application/json");
        post.addHeader("Cookie", cookie);
        post.addHeader("Referer", config.getFreeIpaUrl() + "/ipa");  // CSRF guard
        post.setEntity(new StringEntity(jsonBody, ContentType.APPLICATION_JSON));

        try (CloseableHttpResponse resp = httpClient.execute(post)) {
            int status = resp.getCode();
            if (status == 401) {
                return null; // signal to refresh session
            }
            if (status != 200) {
                throw new Exception("FreeIPA API returned HTTP " + status);
            }
            try {
                return EntityUtils.toString(resp.getEntity(), StandardCharsets.UTF_8);
            } catch (ParseException e) {
                throw new IOException("Failed to parse FreeIPA response", e);
            }
        }
    }

    private void checkApiError(JsonObject response, String method) throws Exception {
        if (response.has("error") && !response.get("error").isJsonNull()) {
            JsonElement err = response.get("error");
            String msg = err.isJsonObject()
                    ? err.getAsJsonObject().get("message").getAsString()
                    : err.toString();
            throw new Exception("FreeIPA " + method + " error: " + msg);
        }
        if (!response.has("result")) {
            throw new Exception("FreeIPA " + method + " response missing 'result'");
        }
    }

    /**
     * Build the {@code [[positional], {keyword}]} params array used by all FreeIPA
     * JSON-RPC methods.
     *
     * <p>The {@code version} field pins the API to a stable revision so that
     * FreeIPA server upgrades don't silently alter response shapes.
     * "2.251" is the API level shipped with FreeIPA 4.9+ / RHEL 8.
     */
    private JsonArray buildParams(JsonArray positional, JsonObject keyword) {
        keyword.addProperty("version", "2.251");
        JsonArray params = new JsonArray();
        params.add(positional);
        params.add(keyword);
        return params;
    }

    // ── HTTP client factory ─────────────────────────────────────────────────

    private CloseableHttpClient buildHttpClient() {
        try {
            SSLContext sslContext;

            if (config.isSkipFreeIpaTlsVerify()) {
                logger.warn("TLS verification for FreeIPA is DISABLED – only use this in lab environments");
                sslContext = SSLContextBuilder.create()
                        .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                        .build();
            } else if (config.getFreeIpaTruststorePath() != null && !config.getFreeIpaTruststorePath().isBlank()) {
                KeyStore ts = KeyStore.getInstance("PKCS12");
                try (FileInputStream fis = new FileInputStream(config.getFreeIpaTruststorePath())) {
                    ts.load(fis, config.getFreeIpaTruststorePassword().toCharArray());
                }
                sslContext = SSLContexts.custom().loadTrustMaterial(ts, null).build();
                logger.info("Loaded FreeIPA trust store from {}", config.getFreeIpaTruststorePath());
            } else {
                sslContext = SSLContexts.createDefault();
            }

            return HttpClients.custom()
                    .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                            .setSSLSocketFactory(
                                    SSLConnectionSocketFactoryBuilder.create()
                                            .setSslContext(sslContext)
                                            .build())
                            .build())
                    .disableRedirectHandling()
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build FreeIPA HTTP client", e);
        }
    }
}
