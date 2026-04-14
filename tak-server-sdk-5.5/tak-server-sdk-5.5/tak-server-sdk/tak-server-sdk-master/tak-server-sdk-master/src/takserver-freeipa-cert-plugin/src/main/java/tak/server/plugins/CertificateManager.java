package tak.server.plugins;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.lang.invoke.MethodHandles;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Handles all PKI operations needed for certificate enrollment:
 *
 * <ol>
 *   <li>Generate an RSA key pair for the ATAK client.</li>
 *   <li>Build a PKCS#10 CSR from the key pair and user identity.</li>
 *   <li>Orchestrate the full enrollment flow: validate user, submit CSR to
 *       FreeIPA, fetch the CA chain, and assemble the final PKCS#12 bundle.</li>
 * </ol>
 *
 * <p>The resulting PKCS#12 bundle contains:
 * <ul>
 *   <li>{@code client} – user private key + FreeIPA-signed user certificate</li>
 *   <li>{@code ca}     – FreeIPA CA certificate (trust anchor)</li>
 * </ul>
 *
 * <p>ATAK imports this bundle directly via the Import Manager or the
 * certificate-enrollment wizard.
 */
public class CertificateManager {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static {
        // Register Bouncy Castle as a JCE provider (idempotent)
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final FreeIPAConfig config;
    private final FreeIPAApiClient apiClient;

    public CertificateManager(FreeIPAConfig config, FreeIPAApiClient apiClient) {
        this.config    = config;
        this.apiClient = apiClient;
    }

    // ── Enrollment result ───────────────────────────────────────────────────

    /** Carries the outputs of a successful enrollment. */
    public static class EnrollmentResult {
        /** Base64-encoded PKCS#12 bundle (user key + cert + CA chain) */
        public final String p12Base64;
        /** Password that protects the PKCS#12 bundle */
        public final String p12Password;
        /** PEM-encoded CA certificate (FreeIPA root CA) */
        public final String caCertPem;
        /** Decimal serial number of the issued certificate */
        public final String certificateSerial;

        EnrollmentResult(String p12Base64, String p12Password,
                         String caCertPem, String certificateSerial) {
            this.p12Base64        = p12Base64;
            this.p12Password      = p12Password;
            this.caCertPem        = caCertPem;
            this.certificateSerial = certificateSerial;
        }
    }

    /**
     * Carries the outputs of signing an externally generated CSR
     * (the {@code POST /Marti/api/tls/signClient/v2} path).
     *
     * <p>Certificates are stored as <b>base64-encoded DER without PEM headers</b>,
     * matching the {@code Util.certToPEM(cert, false)} format used by the official
     * TAK Server ({@code CertManagerApi.java}).  WinTAK/ATAK commo decodes the
     * XML element text directly as base64 DER; embedding PEM headers causes an
     * {@code EXCEPTION_ACCESS_VIOLATION} crash in the native crypto code.
     */
    public static class CsrSignResult {
        /** Base64-encoded DER signed certificate (no {@code -----BEGIN/END-----} headers). */
        public final String signedCertDerBase64;
        /**
         * Base64-encoded DER CA certificates in chain order, no PEM headers
         * (issuing CA first, root CA last).
         */
        public final List<String> caCertDerBase64List;

        CsrSignResult(String signedCertDerBase64, List<String> caCertDerBase64List) {
            this.signedCertDerBase64  = signedCertDerBase64;
            this.caCertDerBase64List  = caCertDerBase64List;
        }
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /**
     * Full enrollment flow for the given user:
     *
     * <ol>
     *   <li>Validate credentials against FreeIPA.</li>
     *   <li>Verify the FreeIPA user account is active.</li>
     *   <li>Generate an RSA key pair.</li>
     *   <li>Build and sign a PKCS#10 CSR.</li>
     *   <li>Submit the CSR to FreeIPA and receive the signed certificate.</li>
     *   <li>Fetch the FreeIPA CA certificate.</li>
     *   <li>Assemble and return a PKCS#12 bundle.</li>
     * </ol>
     *
     * @param username plain ATAK username (must exist in FreeIPA LDAP)
     * @param password the user's FreeIPA password
     * @return populated {@link EnrollmentResult}
     * @throws SecurityException if credential or account validation fails
     * @throws Exception         for any other error
     */
    public EnrollmentResult enroll(String username, String password) throws Exception {
        return enroll(username, password, null);
    }

    /**
     * Full enrollment flow, with an optional per-request PKCS#12 password override.
     *
     * @param username         plain ATAK username (must exist in FreeIPA LDAP)
     * @param password         the user's FreeIPA password
     * @param certPasswordOverride if non-null, used instead of the configured default
     * @return populated {@link EnrollmentResult}
     */
    public EnrollmentResult enroll(String username, String password,
                                   String certPasswordOverride) throws Exception {
        // 1. Validate credentials
        if (!apiClient.validateUserCredentials(username, password)) {
            throw new SecurityException("Invalid credentials for user: " + username);
        }
        logger.info("Credentials validated for user={}", username);

        // 2. Ensure the account is active in FreeIPA
        if (!apiClient.userExists(username)) {
            throw new SecurityException("User account not found or is disabled in FreeIPA: " + username);
        }

        // 3. Generate RSA key pair
        KeyPair keyPair = generateKeyPair();
        logger.debug("Generated RSA-{} key pair for user={}", config.getRsaKeySize(), username);

        // 4. Build PKCS#10 CSR
        String csrPem = buildCsrPem(username, keyPair);
        logger.debug("Built CSR for user={}", username);

        // 5. Submit to FreeIPA
        String certDerBase64 = apiClient.requestCertificate(username, csrPem);
        X509Certificate userCert = derBase64ToCert(certDerBase64);
        String serialHex = userCert.getSerialNumber().toString(16).toUpperCase();
        logger.info("Received signed cert for user={} serial={}", username, serialHex);

        // 6. Fetch CA cert
        String caCertPem = apiClient.getCaCertificatePem();
        X509Certificate caCert = pemFirstCert(caCertPem);
        logger.debug("Fetched FreeIPA CA certificate");

        // 7. Assemble PKCS#12 — use override password if supplied, else configured default
        String p12Password = (certPasswordOverride != null && !certPasswordOverride.isBlank())
                ? certPasswordOverride
                : config.getCertPassword();
        byte[] p12Bytes = buildP12(username, keyPair, userCert, caCert, p12Password);
        String p12Base64 = Base64.getEncoder().encodeToString(p12Bytes);

        return new EnrollmentResult(p12Base64, p12Password, caCertPem, serialHex);
    }

    /**
     * Validate the supplied credentials against FreeIPA.
     *
     * <p>Delegates to {@link FreeIPAApiClient#validateUserCredentials}.  Exposed
     * here so handlers in {@link FreeIPAEnrollmentServer} do not need a direct
     * reference to the API client.
     *
     * @return {@code true} if FreeIPA accepts the credentials
     */
    public boolean validateCredentials(String username, String password) {
        return apiClient.validateUserCredentials(username, password);
    }

    /**
     * Build an in-memory PKCS#12 truststore containing every CA certificate in
     * the FreeIPA CA chain.
     *
     * <p>Delivered to ATAK/WinTAK clients via
     * {@code GET /Marti/api/tls/profile/enrollment} so they can trust the
     * TAK Server's server certificate on port 8089.
     *
     * @param password protects the returned PKCS#12 archive (typically "atakatak")
     * @return raw bytes of the PKCS#12 truststore
     */
    public byte[] buildEnrollmentTruststoreP12(String password) throws Exception {
        String caChainPem = apiClient.getCaCertificatePem();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<java.security.cert.Certificate> caCerts = new ArrayList<>();

        String remaining = caChainPem;
        final String BEGIN = "-----BEGIN CERTIFICATE-----";
        final String END   = "-----END CERTIFICATE-----";
        while (true) {
            int begin = remaining.indexOf(BEGIN);
            int end   = remaining.indexOf(END);
            if (begin == -1 || end == -1) break;
            String body = remaining.substring(begin + BEGIN.length(), end)
                                   .replaceAll("\\s", "");
            if (!body.isEmpty()) {
                byte[] der = Base64.getDecoder().decode(body);
                caCerts.add(cf.generateCertificate(new ByteArrayInputStream(der)));
            }
            remaining = remaining.substring(end + END.length());
        }

        if (caCerts.isEmpty()) {
            throw new Exception("No CA certificates found in FreeIPA CA chain response");
        }

        KeyStore ts = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        ts.load(null, null);
        for (int i = 0; i < caCerts.size(); i++) {
            ts.setCertificateEntry("ca" + i, caCerts.get(i));
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ts.store(baos, password.toCharArray());
        logger.debug("Built enrollment truststore PKCS12 with {} CA cert(s)", caCerts.size());
        return baos.toByteArray();
    }

    /**
     * Sign a client-supplied CSR via FreeIPA and return the signed certificate
     * together with the full CA chain.
     *
     * <p>This is the server-side logic for {@code POST /Marti/api/tls/signClient/v2}.
     * Unlike {@link #enroll}, the private key is generated on the client (WinTAK /
     * ATAK); we receive the PKCS#10 CSR, validate the user, submit it to FreeIPA,
     * and return the PEM-encoded signed certificate plus the CA chain so the
     * client can build its trust store.
     *
     * @param username plain ATAK username (must exist in FreeIPA LDAP)
     * @param password the user's FreeIPA password
     * @param csrPem   PEM-encoded PKCS#10 certificate signing request
     * @return {@link CsrSignResult} with the signed cert and CA chain
     * @throws SecurityException if credential or account validation fails
     * @throws Exception         for any other error
     */
    public CsrSignResult signExternalCsr(String username, String password,
                                         String csrPem) throws Exception {
        // 1. Validate credentials
        if (!apiClient.validateUserCredentials(username, password)) {
            throw new SecurityException("Invalid credentials for user: " + username);
        }
        logger.info("Credentials validated for user={} (signClient/v2)", username);

        // 2. Ensure the account is active
        if (!apiClient.userExists(username)) {
            throw new SecurityException(
                    "User account not found or is disabled in FreeIPA: " + username);
        }

        // 3. Submit client-provided CSR to FreeIPA.
        //    FreeIPA returns the cert as base64-encoded DER — use it directly.
        //    Decode to X509Certificate only to log the serial number.
        String certDerBase64 = apiClient.requestCertificate(username, csrPem);
        String signedCertDerBase64 = certDerBase64.replaceAll("\\s", "");
        X509Certificate signedCert = derBase64ToCert(signedCertDerBase64);
        String serialHex = signedCert.getSerialNumber().toString(16).toUpperCase();
        logger.info("FreeIPA signed cert for user={} serial={} (signClient/v2)",
                username, serialHex);

        // 4. Fetch CA chain and extract each cert as base64 DER (no PEM headers).
        //    This matches Util.certToPEM(cert, false) in the official TAK Server.
        String caChainPem = apiClient.getCaCertificatePem();
        List<String> caDerBase64List = pemChainToDerBase64List(caChainPem);

        return new CsrSignResult(signedCertDerBase64, caDerBase64List);
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(config.getRsaKeySize());
        return kpg.generateKeyPair();
    }

    /**
     * Create a PKCS#10 CSR with the subject {@code CN=<username>,O=<org>,C=<country>}
     * and return it as a PEM string.
     */
    private String buildCsrPem(String username, KeyPair keyPair) throws Exception {
        String subject = "CN=" + sanitizeDnComponent(username)
                + ",O=" + sanitizeDnComponent(config.getCertOrganisation())
                + ",C=" + sanitizeDnComponent(config.getCertCountry());

        X500Name x500Name = new X500Name(subject);
        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(x500Name, keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());

        PKCS10CertificationRequest csr = builder.build(signer);

        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(csr);
        }
        return sw.toString();
    }

    /**
     * Build a PKCS#12 key store containing the user's private key, the
     * FreeIPA-signed user certificate, and the FreeIPA CA certificate.
     *
     * <p>The resulting bundle can be imported directly into ATAK.
     *
     * @param alias    friendly name for the user entry (usually the username)
     * @param keyPair  the generated key pair
     * @param userCert signed user certificate from FreeIPA
     * @param caCert   FreeIPA CA certificate
     * @return raw bytes of the PKCS#12 archive
     */
    private byte[] buildP12(String alias, KeyPair keyPair,
                             X509Certificate userCert,
                             X509Certificate caCert,
                             String p12Password) throws Exception {

        char[] password = p12Password.toCharArray();

        KeyStore p12 = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        p12.load(null, null);

        // User private key entry: chain = [user cert, CA cert]
        p12.setKeyEntry(
                alias,
                keyPair.getPrivate(),
                password,
                new java.security.cert.Certificate[]{userCert, caCert}
        );

        // CA cert as a trusted certificate entry (helps ATAK validate the server)
        p12.setCertificateEntry("ca", caCert);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        p12.store(baos, password);
        return baos.toByteArray();
    }

    /** Decode a base64-DER string (FreeIPA format) to an X.509 certificate. */
    private X509Certificate derBase64ToCert(String base64Der) throws Exception {
        byte[] der = Base64.getDecoder().decode(base64Der.replaceAll("\\s", ""));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    /**
     * Parse the first PEM-encoded certificate from {@code pem}.
     *
     * <p>Handles both single-certificate PEM and concatenated certificate chains
     * (e.g. when FreeIPA is subordinate to an external CA and
     * {@code /ipa/config/ca.crt} returns multiple blocks). Only the first
     * certificate (the issuing CA) is needed as the trust anchor in the PKCS#12.
     */
    private X509Certificate pemFirstCert(String pem) throws Exception {
        // Extract the base64 body of the first PEM block only, so that
        // concatenated chains don't corrupt the base64 decode step.
        int begin = pem.indexOf("-----BEGIN CERTIFICATE-----");
        int end   = pem.indexOf("-----END CERTIFICATE-----");
        if (begin == -1 || end == -1) {
            throw new Exception("No PEM certificate block found in CA response");
        }
        String body = pem.substring(begin + "-----BEGIN CERTIFICATE-----".length(), end)
                         .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    /**
     * Split a PEM certificate chain and return each certificate as
     * <b>base64-encoded DER without PEM headers</b>.
     *
     * <p>Equivalent to calling {@code Util.certToPEM(cert, false)} (no headers)
     * for each certificate in the official TAK Server implementation.
     * WinTAK/ATAK commo decodes the {@code <signedCert>} and {@code <ca>} XML
     * element text directly as raw base64 DER; PEM headers in the element text
     * cause an {@code EXCEPTION_ACCESS_VIOLATION} crash in the native parser.
     *
     * <p>FreeIPA's {@code /ipa/config/ca.crt} endpoint may return a chain when
     * FreeIPA itself is signed by an external root CA.
     */
    private List<String> pemChainToDerBase64List(String pemChain) {
        List<String> result = new ArrayList<>();
        if (pemChain == null) return result;
        String remaining = pemChain;
        final String BEGIN = "-----BEGIN CERTIFICATE-----";
        final String END   = "-----END CERTIFICATE-----";
        while (true) {
            int begin = remaining.indexOf(BEGIN);
            int end   = remaining.indexOf(END);
            if (begin == -1 || end == -1) break;
            // Strip headers and all whitespace → raw base64 DER
            String base64 = remaining.substring(begin + BEGIN.length(), end)
                                     .replaceAll("\\s", "");
            if (!base64.isEmpty()) result.add(base64);
            remaining = remaining.substring(end + END.length());
        }
        return result;
    }

    /**
     * Sanitise a value before embedding it in an X.500 DN to prevent
     * DN injection (e.g. a username like {@code foo,O=evil}).
     */
    private static String sanitizeDnComponent(String value) {
        if (value == null) return "";
        // Escape characters that are special in DN strings
        return value.replaceAll("[,=+<>#;\"\\\\]", "");
    }
}
