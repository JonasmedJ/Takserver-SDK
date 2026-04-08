package tak.server.plugins;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandles;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Base64;
import java.util.concurrent.Executors;

/**
 * Embedded HTTPS server that exposes a TAK-compatible certificate-enrollment
 * endpoint.
 *
 * <h3>Endpoint</h3>
 * {@code POST https://<host>:<enrollmentPort>/Marti/enrollment/enrollment}
 *
 * <h3>Authentication</h3>
 * HTTP Basic Auth header – {@code Authorization: Basic base64(username:password)}.
 * Credentials are validated against FreeIPA before any certificate is issued.
 *
 * <h3>Request body (optional JSON)</h3>
 * <pre>{@code
 * {
 *   "uid":          "<device UID>",
 *   "certPassword": "<desired p12 password>"   // overrides plugin default
 * }
 * }</pre>
 *
 * <h3>Success response (200)</h3>
 * <pre>{@code
 * {
 *   "enrolled":          true,
 *   "description":       "Certificate enrollment successful",
 *   "p12":               "<base64-PKCS12>",
 *   "p12Password":       "atakatak",
 *   "ca":                "<PEM CA certificate>",
 *   "certificateSerial": "<hex serial>"
 * }
 * }</pre>
 *
 * <h3>Error response (4xx / 5xx)</h3>
 * <pre>{@code { "enrolled": false, "error": "<message>" } }</pre>
 *
 * <h3>ATAK configuration</h3>
 * This plugin runs on port 8446 as a drop-in replacement for TAK Server's
 * built-in enrollment service.  ATAK users enroll exactly as normal – no
 * client-side changes required.
 * Disable TAK Server's built-in 8446 connector in CoreConfig.xml before deploying.
 */
public class FreeIPAEnrollmentServer {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private static final String ENROLLMENT_PATH = "/Marti/enrollment/enrollment";
    private static final String HEALTH_PATH      = "/Marti/enrollment/health";

    private final FreeIPAConfig      config;
    private final CertificateManager certMgr;
    private final Gson               gson = new Gson();

    private HttpsServer server;

    public FreeIPAEnrollmentServer(FreeIPAConfig config, CertificateManager certMgr) {
        this.config  = config;
        this.certMgr = certMgr;
    }

    // ── Lifecycle ───────────────────────────────────────────────────────────

    public void start() {
        try {
            SSLContext sslContext = buildSslContext();

            server = HttpsServer.create(
                    new InetSocketAddress(config.getEnrollmentPort()), 32);

            server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                @Override
                public void configure(HttpsParameters params) {
                    SSLContext ctx = getSSLContext();
                    SSLParameters sslParams = ctx.getDefaultSSLParameters();
                    // Do not require client certificates – ATAK presents none on first enroll
                    sslParams.setNeedClientAuth(false);
                    sslParams.setWantClientAuth(false);
                    params.setSSLParameters(sslParams);
                }
            });

            server.createContext(ENROLLMENT_PATH, new EnrollmentHandler());
            server.createContext(HEALTH_PATH,      new HealthHandler());

            // Thread pool: 10 concurrent enrollment requests
            server.setExecutor(Executors.newFixedThreadPool(10));
            server.start();

            logger.info("FreeIPA enrollment HTTPS server listening on port {}", config.getEnrollmentPort());
        } catch (Exception e) {
            throw new RuntimeException("Failed to start enrollment server on port "
                    + config.getEnrollmentPort(), e);
        }
    }

    public void stop() {
        if (server != null) {
            server.stop(3);  // allow 3 s for in-flight requests to complete
            logger.info("Enrollment server stopped");
        }
    }

    // ── SSL context ─────────────────────────────────────────────────────────

    private SSLContext buildSslContext() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(config.getKeystorePath())) {
            ks.load(fis, config.getKeystorePassword().toCharArray());
        }
        logger.info("Loaded server keystore from {}", config.getKeystorePath());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, config.getKeystorePassword().toCharArray());

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    // ── Request handlers ────────────────────────────────────────────────────

    /** Handles {@code /Marti/enrollment/enrollment} (POST = enroll, GET = ping). */
    private class EnrollmentHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();
            try {
                if ("POST".equalsIgnoreCase(method)) {
                    handleEnrollment(exchange);
                } else if ("GET".equalsIgnoreCase(method)) {
                    sendJson(exchange, 200, buildOk("FreeIPA enrollment endpoint active"));
                } else {
                    sendJson(exchange, 405, buildError("Method not allowed"));
                }
            } catch (Exception e) {
                logger.error("Unhandled error in enrollment handler", e);
                try {
                    sendJson(exchange, 500, buildError("Internal server error"));
                } catch (Exception ignored) { }
            }
        }

        private void handleEnrollment(HttpExchange exchange) throws IOException {
            // 1. Parse Basic Auth credentials
            String[] credentials = extractBasicAuth(exchange);
            if (credentials == null) {
                exchange.getResponseHeaders().add("WWW-Authenticate",
                        "Basic realm=\"TAK FreeIPA Enrollment\"");
                sendJson(exchange, 401, buildError("Authentication required"));
                return;
            }
            String username = credentials[0];
            String password = credentials[1];

            // Read optional JSON body (ignore on parse error)
            String bodyStr = "";
            try (InputStream is = exchange.getRequestBody()) {
                bodyStr = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            } catch (Exception ignored) { }

            logger.info("Enrollment request from user={} remoteAddr={}",
                    username, exchange.getRemoteAddress());

            // 2. Run enrollment
            CertificateManager.EnrollmentResult result;
            try {
                result = certMgr.enroll(username, password);
            } catch (SecurityException se) {
                logger.warn("Enrollment rejected for user={}: {}", username, se.getMessage());
                exchange.getResponseHeaders().add("WWW-Authenticate",
                        "Basic realm=\"TAK FreeIPA Enrollment\"");
                sendJson(exchange, 401, buildError(se.getMessage()));
                return;
            } catch (Exception e) {
                logger.error("Enrollment failed for user={}", username, e);
                sendJson(exchange, 500, buildError("Certificate issuance failed: " + e.getMessage()));
                return;
            }

            // 3. Build success response
            JsonObject resp = new JsonObject();
            resp.addProperty("enrolled",          true);
            resp.addProperty("description",       "Certificate enrollment successful");
            resp.addProperty("p12",               result.p12Base64);
            resp.addProperty("p12Password",       result.p12Password);
            resp.addProperty("ca",                result.caCertPem);
            resp.addProperty("certificateSerial", result.certificateSerial);

            logger.info("Enrollment successful for user={} serial={}", username, result.certificateSerial);
            sendJson(exchange, 200, resp.toString());
        }
    }

    /** Simple liveness probe at {@code /Marti/enrollment/health}. */
    private class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            sendJson(exchange, 200, buildOk("FreeIPA enrollment plugin healthy"));
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /**
     * Decode HTTP Basic Auth from the {@code Authorization} header.
     *
     * @return {@code [username, password]}, or {@code null} if header is absent
     *         or malformed
     */
    private String[] extractBasicAuth(HttpExchange exchange) {
        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Basic ")) {
            return null;
        }
        try {
            String decoded = new String(
                    Base64.getDecoder().decode(authHeader.substring(6)),
                    StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon < 1) return null;
            String user = decoded.substring(0, colon);
            String pass = decoded.substring(colon + 1);
            if (user.isBlank()) return null;
            return new String[]{user, pass};
        } catch (Exception e) {
            return null;
        }
    }

    private void sendJson(HttpExchange exchange, int statusCode, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private String buildError(String message) {
        JsonObject o = new JsonObject();
        o.addProperty("enrolled", false);
        o.addProperty("error", message);
        return o.toString();
    }

    private String buildOk(String message) {
        JsonObject o = new JsonObject();
        o.addProperty("status", "ok");
        o.addProperty("message", message);
        return o.toString();
    }
}
