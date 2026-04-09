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
import java.util.Base64;

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
        X509Certificate caCert = pemToCert(caCertPem);
        logger.debug("Fetched FreeIPA CA certificate");

        // 7. Assemble PKCS#12
        byte[] p12Bytes = buildP12(username, keyPair, userCert, caCert);
        String p12Base64 = Base64.getEncoder().encodeToString(p12Bytes);

        return new EnrollmentResult(p12Base64, config.getCertPassword(), caCertPem, serialHex);
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
                             X509Certificate caCert) throws Exception {

        char[] password = config.getCertPassword().toCharArray();

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

    /** Parse a PEM-encoded certificate. */
    private X509Certificate pemToCert(String pem) throws Exception {
        // Strip PEM headers and decode
        String stripped = pem
                .replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(stripped);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
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
