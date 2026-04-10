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
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509ExtendedKeyManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandles;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
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

    /**
     * Reloadable key manager used by the fixed {@link SSLContext}.
     *
     * <p>{@link SSLContext} bakes in the key material at construction time, so
     * simply swapping a volatile {@code SSLContext} reference has no effect on
     * in-progress or future TLS handshakes — the engine keeps using the context
     * it was created from.
     *
     * <p>The correct zero-downtime approach is to give the {@code SSLContext} a
     * {@link X509ExtendedKeyManager} whose {@code delegate} is a volatile field.
     * The JDK calls {@link X509ExtendedKeyManager#getPrivateKey} and
     * {@link X509ExtendedKeyManager#getCertificateChain} per-handshake, so
     * updating the delegate is picked up immediately for every new TLS connection
     * without touching the {@code SSLContext} or restarting the server.
     */
    private ReloadableKeyManager reloadableKeyManager;

    public FreeIPAEnrollmentServer(FreeIPAConfig config, CertificateManager certMgr) {
        this.config  = config;
        this.certMgr = certMgr;
    }

    // ── Lifecycle ───────────────────────────────────────────────────────────

    public void start() {
        try {
            SSLContext sslContext = buildSslContext();   // reloadableKeyManager is set inside

            server = HttpsServer.create(
                    new InetSocketAddress(config.getEnrollmentPort()), 32);

            server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                @Override
                public void configure(HttpsParameters params) {
                    SSLParameters sslParams = getSSLContext().getDefaultSSLParameters();
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

    /**
     * Reload the TLS certificate from disk without restarting the server.
     *
     * <p>Intended for use with Let's Encrypt (or any short-lived cert) where an
     * ACME client (e.g. certbot) renews the certificate periodically. Wire this
     * into a certbot deploy hook:
     *
     * <pre>
     * # /etc/letsencrypt/renewal-hooks/deploy/tak-freeipa-enrollment.sh
     * #!/bin/bash
     * set -e
     * # Convert renewed PEM files to PKCS12 in place
     * openssl pkcs12 -export \
     *   -in  /etc/letsencrypt/live/takserver.example.com/fullchain.pem \
     *   -inkey /etc/letsencrypt/live/takserver.example.com/privkey.pem \
     *   -out /opt/tak/certs/enrollment.p12 \
     *   -passout pass:atakatak
     * # Signal the service to pick up the new cert (ExecReload=kill -HUP $MAINPID)
     * systemctl reload freeipa-enrollment
     * </pre>
     *
     * <p>In-flight enrollment requests complete against the old context;
     * new connections immediately use the renewed certificate.
     */
    /**
     * Hot-reload the TLS certificate from disk.
     *
     * <p>The {@link SSLContext} is fixed for the lifetime of the server process,
     * but its {@link ReloadableKeyManager} holds the key material behind a
     * {@code volatile} reference. Updating that reference is immediately visible
     * to every subsequent TLS handshake — no server restart or connection drain
     * required.
     *
     * <p>Wire this into a certbot deploy hook:
     * <pre>
     * # /etc/letsencrypt/renewal-hooks/deploy/tak-freeipa-enrollment.sh
     * #!/bin/bash
     * set -e
     * openssl pkcs12 -export \
     *   -in  /etc/letsencrypt/live/takserver.example.com/fullchain.pem \
     *   -inkey /etc/letsencrypt/live/takserver.example.com/privkey.pem \
     *   -out /opt/tak/certs/enrollment.p12 \
     *   -passout pass:atakatak
     * systemctl reload freeipa-enrollment   # sends SIGHUP
     * </pre>
     */
    public void reloadSslContext() throws Exception {
        X509ExtendedKeyManager fresh = loadKeyManager();
        reloadableKeyManager.update(fresh);
        logger.info("TLS key material reloaded from {} (Let's Encrypt renewal or manual trigger)",
                config.getKeystorePath());
    }

    // ── SSL context ─────────────────────────────────────────────────────────

    /**
     * Build the {@link SSLContext} once for the lifetime of the server.
     * Key material is held in {@link #reloadableKeyManager} so it can be
     * swapped later without touching the context.
     */
    private SSLContext buildSslContext() throws Exception {
        X509ExtendedKeyManager initial = loadKeyManager();
        reloadableKeyManager = new ReloadableKeyManager(initial);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(new javax.net.ssl.KeyManager[]{ reloadableKeyManager }, null, null);
        return ctx;
    }

    /** Load the {@link X509ExtendedKeyManager} from the configured PKCS12 keystore. */
    private X509ExtendedKeyManager loadKeyManager() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(config.getKeystorePath())) {
            ks.load(fis, config.getKeystorePassword().toCharArray());
        }
        logger.info("Loaded server keystore from {}", config.getKeystorePath());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, config.getKeystorePassword().toCharArray());

        return Arrays.stream(kmf.getKeyManagers())
                .filter(km -> km instanceof X509ExtendedKeyManager)
                .map(km -> (X509ExtendedKeyManager) km)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "No X509ExtendedKeyManager found in keystore " + config.getKeystorePath()));
    }

    // ── ReloadableKeyManager ─────────────────────────────────────────────────

    /**
     * An {@link X509ExtendedKeyManager} whose key material is held in a
     * {@code volatile} delegate so it can be atomically swapped at runtime.
     * The JDK calls {@link #getPrivateKey} and {@link #getCertificateChain}
     * on every TLS handshake, so updating the delegate is immediately visible
     * to all new connections.
     */
    private static final class ReloadableKeyManager extends X509ExtendedKeyManager {

        private volatile X509ExtendedKeyManager delegate;

        ReloadableKeyManager(X509ExtendedKeyManager initial) {
            this.delegate = initial;
        }

        void update(X509ExtendedKeyManager next) {
            this.delegate = next;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return delegate.getClientAliases(keyType, issuers);
        }

        @Override
        public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
            return delegate.chooseClientAlias(keyTypes, issuers, socket);
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return delegate.getServerAliases(keyType, issuers);
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return delegate.chooseServerAlias(keyType, issuers, socket);
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return delegate.chooseEngineServerAlias(keyType, issuers, engine);
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return delegate.getCertificateChain(alias);
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return delegate.getPrivateKey(alias);
        }
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

            // Read optional JSON body with a 64 KB size guard to prevent DoS
            String bodyStr = "";
            try (InputStream is = exchange.getRequestBody()) {
                byte[] buf = is.readNBytes(65536);
                bodyStr = new String(buf, StandardCharsets.UTF_8);
            } catch (Exception ignored) { }

            // Parse optional fields from the JSON body
            String certPasswordOverride = null;
            if (!bodyStr.isBlank()) {
                try {
                    JsonObject bodyJson = com.google.gson.JsonParser.parseString(bodyStr).getAsJsonObject();
                    if (bodyJson.has("certPassword") && !bodyJson.get("certPassword").isJsonNull()) {
                        certPasswordOverride = bodyJson.get("certPassword").getAsString();
                    }
                } catch (Exception ignored) { }
            }

            logger.info("Enrollment request from user={} remoteAddr={}",
                    username, exchange.getRemoteAddress());

            // 2. Run enrollment
            CertificateManager.EnrollmentResult result;
            try {
                result = certMgr.enroll(username, password, certPasswordOverride);
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
