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
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
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
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Embedded HTTPS server that exposes a TAK-compatible certificate-enrollment
 * endpoint.
 *
 * <h3>Endpoints</h3>
 * <ul>
 *   <li>{@code GET  /Marti/api/tls/config}         – csrconfig (XML {@code <certificateConfig>})</li>
 *   <li>{@code POST /Marti/api/tls/signClient/v2}  – CSR signing (XML {@code <enrollment>} or JSON)</li>
 *   <li>{@code POST /Marti/enrollment/enrollment}  – legacy PKCS#12 enrollment (JSON)</li>
 * </ul>
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

    private static final String ENROLLMENT_PATH     = "/Marti/enrollment/enrollment";
    private static final String HEALTH_PATH          = "/Marti/enrollment/health";
    /** WinTAK 5.x fetches this before submitting a CSR. */
    private static final String TLS_CONFIG_PATH      = "/Marti/api/tls/config";
    /**
     * WinTAK 5.x / ATAK commo (libcommo 1.14+) posts the client CSR here.
     * The server signs it with FreeIPA and returns JSON with the signed cert
     * and CA chain — no PKCS#12 involved; the client already holds the private key.
     */
    private static final String SIGN_CLIENT_V2_PATH  = "/Marti/api/tls/signClient/v2";
    /**
     * ATAK / WinTAK fetch this after signing to obtain the TAK Server CA trust
     * material.  Response is a TAK Data Package (ZIP) containing a PKCS#12
     * truststore so the client can validate the server's certificate on port 8089.
     */
    private static final String ENROLLMENT_PROFILE_PATH = "/Marti/api/tls/profile/enrollment";

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

            server.createContext(ENROLLMENT_PATH,         new EnrollmentHandler());
            server.createContext(HEALTH_PATH,              new HealthHandler());
            server.createContext(TLS_CONFIG_PATH,          new TlsConfigHandler());
            server.createContext(SIGN_CLIENT_V2_PATH,      new SignClientV2Handler());
            server.createContext(ENROLLMENT_PROFILE_PATH,  new EnrollmentProfileHandler());

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

    /**
     * WinTAK 5.x hits {@code GET /Marti/api/tls/config} during its "csrconfig"
     * enrollment phase to learn what subject fields to embed in the CSR.
     * The response tells the client that Basic-Auth enrollment is in use and
     * supplies the org/country values from the plugin config so the CSR subject
     * matches what FreeIPA will sign.
     *
     * <p>After receiving this response WinTAK proceeds to
     * {@code POST /Marti/enrollment/enrollment} with the Basic Auth header and
     * a JSON body containing the generated CSR — exactly the endpoint this
     * plugin already implements.
     */
    private class TlsConfigHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    sendJson(exchange, 405, buildError("Method not allowed"));
                    return;
                }
                // WinTAK/ATAK commo (libcommo) expects root element "certificateConfig"
                // with validityDays attribute, and nameEntry elements using XML attributes
                // (not child elements) for name/value pairs.
                // Reference: goatak enroll.go CertificateConfig struct.
                String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
                        + "<certificateConfig validityDays=\"7305\">\n"
                        + "  <nameEntries>\n"
                        + "    <nameEntry name=\"O\" value=\""
                        + escapeXml(config.getCertOrganisation())
                        + "\"/>\n"
                        + "    <nameEntry name=\"C\" value=\""
                        + escapeXml(config.getCertCountry())
                        + "\"/>\n"
                        + "  </nameEntries>\n"
                        + "</certificateConfig>";
                sendXml(exchange, 200, xml);
            } catch (Exception e) {
                logger.error("Unhandled error in TLS config handler", e);
                try { sendJson(exchange, 500, buildError("Internal server error")); }
                catch (Exception ignored) { }
            }
        }
    }

    /**
     * Handles {@code POST /Marti/api/tls/signClient/v2}.
     *
     * <p>WinTAK 5.x / ATAK commo (libcommo 1.14+) posts a PEM-encoded PKCS#10
     * CSR here after obtaining csrconfig and sends {@code Accept: application/xml}.
     * The response format is content-negotiated (matching goatak server behaviour):
     *
     * <ul>
     *   <li>{@code Accept: application/xml} → XML enrollment document (WinTAK, ATAK)</li>
     *   <li>{@code Accept: application/json} or {@code *}{@code /*} → JSON (goatak client)</li>
     * </ul>
     *
     * <p>XML response (root element {@code <enrollment>}):
     * <pre>{@code
     * <?xml version="1.0" encoding="UTF-8"?>
     * <enrollment>
     *   <signedCert>MIIFx...base64DER...</signedCert>
     *   <ca>MIIGx...base64DER...</ca>
     * </enrollment>
     * }</pre>
     *
     * <p>Certificate content is <b>base64-encoded DER with no PEM headers</b>,
     * matching {@code Util.certToPEM(cert, false)} from the official TAK Server.
     * Embedding PEM headers (-----BEGIN/END-----) crashes WinTAK commo with
     * {@code EXCEPTION_ACCESS_VIOLATION}.
     *
     * <p>JSON fallback:
     * <pre>{@code {"signedCert": "base64DER", "ca0": "base64DER", "ca1": "base64DER"} }</pre>
     */
    private class SignClientV2Handler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    sendJson(exchange, 405, buildError("Method not allowed"));
                    return;
                }

                // 1. Parse Basic Auth
                String[] credentials = extractBasicAuth(exchange);
                if (credentials == null) {
                    exchange.getResponseHeaders().add("WWW-Authenticate",
                            "Basic realm=\"TAK FreeIPA Enrollment\"");
                    sendJson(exchange, 401, buildError("Authentication required"));
                    return;
                }
                String username = credentials[0];
                String password = credentials[1];

                // 2. Read PEM CSR from body (max 64 KB guard)
                String csrPem;
                try (InputStream is = exchange.getRequestBody()) {
                    byte[] buf = is.readNBytes(65536);
                    csrPem = new String(buf, StandardCharsets.UTF_8).trim();
                }

                if (csrPem.isEmpty()) {
                    sendJson(exchange, 400, buildError("Empty request body – expected PEM CSR"));
                    return;
                }

                // Log Accept header to confirm WinTAK sends application/xml
                String acceptHeader = exchange.getRequestHeaders().getFirst("Accept");
                logger.info("signClient/v2 request from user={} remoteAddr={} Accept={}",
                        username, exchange.getRemoteAddress(), acceptHeader);

                // 3. Validate credentials and sign CSR via FreeIPA
                CertificateManager.CsrSignResult result;
                try {
                    result = certMgr.signExternalCsr(username, password, csrPem);
                } catch (SecurityException se) {
                    logger.warn("signClient/v2 rejected for user={}: {}", username, se.getMessage());
                    exchange.getResponseHeaders().add("WWW-Authenticate",
                            "Basic realm=\"TAK FreeIPA Enrollment\"");
                    sendJson(exchange, 401, buildError(se.getMessage()));
                    return;
                } catch (Exception e) {
                    logger.error("signClient/v2 failed for user={}", username, e);
                    sendJson(exchange, 500,
                            buildError("Certificate signing failed: " + e.getMessage()));
                    return;
                }

                // 4. Content-negotiate the response format.
                //    WinTAK/ATAK sends Accept: application/xml; goatak sends Accept: */* or
                //    application/json.  Matching goatak server behaviour exactly.
                boolean wantsXml = acceptHeader != null && acceptHeader.contains("application/xml");
                boolean wantsJson = acceptHeader == null
                        || acceptHeader.contains("*/*")
                        || acceptHeader.contains("application/json");

                if (wantsXml) {
                    // XML: base64 DER in each element, no PEM headers.
                    // Matches Util.certToPEM(cert, false) from official TAK Server.
                    StringBuilder xml = new StringBuilder();
                    xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                    xml.append("<enrollment>");
                    xml.append("<signedCert>").append(result.signedCertDerBase64).append("</signedCert>");
                    for (String caDer : result.caCertDerBase64List) {
                        xml.append("<ca>").append(caDer).append("</ca>");
                    }
                    xml.append("</enrollment>");
                    exchange.getResponseHeaders().set("Content-Disposition", "attachment");
                    sendXml(exchange, 200, xml.toString());
                } else if (wantsJson) {
                    // JSON: {"signedCert": "base64DER", "ca0": "base64DER", ...}
                    // CA keys are numbered (ca0, ca1...) matching official TAK Server format.
                    JsonObject resp = new JsonObject();
                    resp.addProperty("signedCert", result.signedCertDerBase64);
                    int idx = 0;
                    for (String caDer : result.caCertDerBase64List) {
                        resp.addProperty("ca" + idx++, caDer);
                    }
                    sendJson(exchange, 200, resp.toString());
                } else {
                    sendJson(exchange, 400, buildError(
                            "Unsupported Accept type – use application/xml or application/json"));
                    return;
                }

                logger.info("signClient/v2 successful for user={}", username);

            } catch (Exception e) {
                logger.error("Unhandled error in signClient/v2 handler", e);
                try { sendJson(exchange, 500, buildError("Internal server error")); }
                catch (Exception ignored) { }
            }
        }
    }

    /** Simple liveness probe at {@code /Marti/enrollment/health}. */
    private class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            sendJson(exchange, 200, buildOk("FreeIPA enrollment plugin healthy"));
        }
    }

    /**
     * Handles {@code GET /Marti/api/tls/profile/enrollment}.
     *
     * <p>ATAK (and WinTAK) fetch this endpoint after {@code signClient/v2} to
     * obtain a TAK Data Package containing the TAK Server CA truststore.  ATAK
     * imports the truststore so it can validate the server's TLS certificate when
     * it connects to port 8089 after enrollment.
     *
     * <p>Response: {@code application/zip} containing:
     * <ul>
     *   <li>{@code MANIFEST/manifest.xml}      – TAK Data Package manifest</li>
     *   <li>{@code certs/truststore-root.p12}  – PKCS#12 with FreeIPA CA cert(s)</li>
     * </ul>
     *
     * <p>The PKCS#12 truststore is either loaded from the path configured by
     * {@code enrollmentTruststorePath} (if set) or built dynamically from the
     * FreeIPA CA chain fetched at request time.
     *
     * <p>Authentication is <b>optional</b>: the real TAK Server does not require
     * credentials on this endpoint (the CA truststore is public information).
     * If a {@code Authorization: Basic} header is present the credentials are
     * validated and the request is rejected on mismatch; an unauthenticated
     * request is served normally after logging the remote address.
     */
    private class EnrollmentProfileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    sendJson(exchange, 405, buildError("Method not allowed"));
                    return;
                }

                // Auth is optional – the real TAK Server serves this endpoint
                // unauthenticated. ATAK does not always send credentials here.
                // If credentials ARE present, validate them so bad actors can't
                // probe which users exist.
                String[] credentials = extractBasicAuth(exchange);
                String username;
                if (credentials != null) {
                    username = credentials[0];
                    if (!certMgr.validateCredentials(username, credentials[1])) {
                        logger.warn("enrollment profile rejected – invalid credentials for user={}", username);
                        exchange.getResponseHeaders().add("WWW-Authenticate",
                                "Basic realm=\"TAK FreeIPA Enrollment\"");
                        sendJson(exchange, 401, buildError("Invalid credentials"));
                        return;
                    }
                } else {
                    // No credentials – serve the profile (CA cert is public info)
                    username = exchange.getRequestHeaders().getFirst("X-TAK-Username");
                    if (username == null || username.isBlank()) username = "anonymous";
                }

                logger.info("enrollment profile request from user={} remoteAddr={}",
                        username, exchange.getRemoteAddress());

                // Obtain the PKCS#12 truststore bytes
                byte[] truststoreBytes;
                String truststorePath = config.getEnrollmentTruststorePath();
                if (truststorePath != null && !truststorePath.isBlank()) {
                    truststoreBytes = Files.readAllBytes(Paths.get(truststorePath));
                    logger.debug("Using pre-configured enrollment truststore from {}", truststorePath);
                } else {
                    truststoreBytes = certMgr.buildEnrollmentTruststoreP12(
                            config.getEnrollmentTruststorePassword());
                    logger.debug("Built enrollment truststore dynamically from FreeIPA CA chain");
                }

                byte[] zipBytes = buildEnrollmentProfileZip(truststoreBytes, username);

                exchange.getResponseHeaders().set("Content-Type", "application/zip");
                exchange.getResponseHeaders().set("Content-Disposition",
                        "attachment; filename=\"enrollment.zip\"");
                exchange.sendResponseHeaders(200, zipBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(zipBytes);
                }

                logger.info("enrollment profile served to user={}", username);

            } catch (Exception e) {
                logger.error("Unhandled error in enrollment profile handler", e);
                try { sendJson(exchange, 500, buildError("Internal server error")); }
                catch (Exception ignored) { }
            }
        }
    }

    /**
     * Build the TAK Data Package ZIP for {@code profile/enrollment}.
     *
     * <p>Structure (matches real TAK Server output):
     * <pre>
     * MANIFEST/manifest.xml        – CoT data package manifest
     * certs/truststore-root.p12    – PKCS#12 containing the CA certs ATAK should trust
     * </pre>
     *
     * <p>The {@code certs/} subdirectory is mandatory: ATAK's import resolver
     * recognises a {@code .p12} inside {@code certs/} as a certificate bundle to
     * import automatically, while a {@code .p12} at the root is treated as an
     * arbitrary attachment and may be ignored.
     */
    private byte[] buildEnrollmentProfileZip(byte[] truststoreP12Bytes, String username) throws IOException {
        final String TRUSTSTORE_FILENAME = "certs/truststore-root.p12";
        final String TRUSTSTORE_NAME     = "truststore-root";
        final String PREFS_FILENAME      = "prefs/com.atakmap.app_preferences.xml";

        // Fetch TAK attributes from FreeIPA for authenticated users
        Map<String, String> takAttrs = Collections.emptyMap();
        if (username != null && !username.isBlank() && !"anonymous".equals(username)) {
            try {
                takAttrs = certMgr.getUserTakAttributes(username);
                logger.info("TAK attributes for user={}: {}", username, takAttrs);
            } catch (Exception e) {
                logger.warn("Could not fetch TAK attributes for user={}, prefs omitted: {}", username, e.getMessage());
            }
        }

        // Build ATAK preferences XML if any attributes are present
        String prefsXml = null;
        if (!takAttrs.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            sb.append("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n");
            if (takAttrs.containsKey("callsign"))
                sb.append("    <string name=\"locationCallsign\">").append(escapeXml(takAttrs.get("callsign"))).append("</string>\n");
            if (takAttrs.containsKey("team"))
                sb.append("    <string name=\"locationTeam\">").append(escapeXml(takAttrs.get("team"))).append("</string>\n");
            if (takAttrs.containsKey("role"))
                sb.append("    <string name=\"atakRoleType\">").append(escapeXml(takAttrs.get("role"))).append("</string>\n");
            sb.append("</map>");
            prefsXml = sb.toString();
        }

        String uid = UUID.randomUUID().toString();

        StringBuilder manifest = new StringBuilder();
        manifest.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
                .append("<MissionPackageManifest version=\"2\">\n")
                .append("  <Configuration>\n")
                .append("    <Parameter name=\"uid\" value=\"").append(uid).append("\"/>\n")
                .append("    <Parameter name=\"name\" value=\"").append(TRUSTSTORE_NAME).append("\"/>\n")
                .append("    <Parameter name=\"onReceiveDelete\" value=\"false\"/>\n")
                .append("  </Configuration>\n")
                .append("  <Contents>\n")
                .append("    <Content ignore=\"false\" zipEntry=\"").append(TRUSTSTORE_FILENAME).append("\">\n")
                .append("      <Parameter name=\"name\" value=\"").append(TRUSTSTORE_NAME).append("\"/>\n")
                .append("    </Content>\n");
        if (prefsXml != null) {
            manifest.append("    <Content ignore=\"false\" zipEntry=\"").append(PREFS_FILENAME).append("\">\n")
                    .append("      <Parameter name=\"name\" value=\"com.atakmap.app_preferences\"/>\n")
                    .append("    </Content>\n");
        }
        manifest.append("  </Contents>\n</MissionPackageManifest>");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(baos)) {
            zip.putNextEntry(new ZipEntry("MANIFEST/manifest.xml"));
            zip.write(manifest.toString().getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();

            zip.putNextEntry(new ZipEntry(TRUSTSTORE_FILENAME));
            zip.write(truststoreP12Bytes);
            zip.closeEntry();

            if (prefsXml != null) {
                zip.putNextEntry(new ZipEntry(PREFS_FILENAME));
                zip.write(prefsXml.getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        }
        return baos.toByteArray();
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

    private void sendXml(HttpExchange exchange, int statusCode, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/xml; charset=utf-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String escapeXml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
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
