import org.openeid.cdoc4j.CDOCBuilder;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.io.*;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.*;
import java.nio.file.Files;
import org.openeid.cdoc4j.DataFile;
import com.ctc.wstx.stax.WstxOutputFactory;
import javax.xml.stream.XMLOutputFactory;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(
    name = "cdoc-encryptor",
    mixinStandardHelpOptions = true,
    version = "1.0",
    description = "Encrypts files using Estonian ID card certificates",
    subcommands = {SimpleCDOCEncryptor.EncryptCommand.class}
)
public class SimpleCDOCEncryptor {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        int exitCode = new CommandLine(new SimpleCDOCEncryptor()).execute(args);
        System.exit(exitCode);
    }

    @Command(name = "encrypt", description = "Encrypt a file using Estonian ID card")
    static class EncryptCommand implements Runnable {

        @Option(names = {"--id"}, required = true, description = "Estonian ID code of the recipient")
        private String personalIdCode;

        @Option(names = {"--input-file"}, required = true, description = "Path to the file to be encrypted")
        private File inputFile;

        @Option(names = {"--verbose"}, description = "Enable verbose logging")
        private boolean verboseEnabled;

        private static final Logger LOGGER = Logger.getLogger(EncryptCommand.class.getName());
        private static final String LDAP_URL = "ldaps://esteid.ldap.sk.ee";

        @Override
        public void run() {
            configureLogging(verboseEnabled);

            try {
                if (!inputFile.exists()) {
                    throw new FileNotFoundException("Input file does not exist: " + inputFile.getAbsolutePath());
                }

                logInfo("Fetching certificate for ID: " + personalIdCode);
                X509Certificate certificate = fetchCertificateFromLDAP(personalIdCode);
                if (certificate == null) {
                    throw new Exception("Could not fetch a suitable encryption certificate for ID: " + personalIdCode);
                }

                XMLOutputFactory xmlOutputFactory = new WstxOutputFactory();
                System.setProperty("javax.xml.stream.XMLOutputFactory", xmlOutputFactory.getClass().getName());

                DataFile dataFile = new DataFile(
                        inputFile.getName(),
                        Files.readAllBytes(inputFile.toPath())
                );

                File outFile = new File(personalIdCode + ".cdoc");
                CDOCBuilder.defaultVersion()
                        .withDataFile(dataFile)
                        .withRecipient(certificate)
                        .buildToFile(outFile);

                logInfo("Encrypted file created at: " + outFile.getAbsolutePath());
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Operation failed: " + e.getMessage(), e);
            }
        }

        private static void configureLogging(boolean verbose) {
            Logger rootLogger = Logger.getLogger("");
            for (Handler handler : rootLogger.getHandlers()) {
                rootLogger.removeHandler(handler);
            }

            ConsoleHandler handler = new ConsoleHandler();
            handler.setFormatter(new java.util.logging.Formatter() {
                private final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");

                @Override
                public String format(LogRecord record) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(sdf.format(new Date(record.getMillis())));
                    sb.append(" [").append(Thread.currentThread().getName()).append("] ");
                    sb.append(record.getLevel().getName()).append("  ");
                    sb.append(record.getMessage()).append("\n");
                    return sb.toString();
                }
            });
            rootLogger.addHandler(handler);
            rootLogger.setLevel(verbose ? Level.INFO : Level.WARNING);
        }

        private static void logInfo(String message) {
            LOGGER.info(message);
        }

        private static X509Certificate fetchCertificateFromLDAP(String idCode) throws Exception {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, LDAP_URL);
            env.put(Context.SECURITY_PROTOCOL, "ssl");

            LdapContext ctx = null;
            try {
                ctx = new InitialLdapContext(env, null);
                String base = "c=EE";
                String filter = "(&(objectClass=person)(serialNumber=PNOEE-" + idCode + "))";
                SearchControls sc = new SearchControls();
                sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
                sc.setReturningAttributes(new String[]{"userCertificate;binary"});

                NamingEnumeration<SearchResult> results = ctx.search(base, filter, sc);
                while (results.hasMore()) {
                    SearchResult sr = results.next();
                    byte[] certBytes = (byte[]) sr.getAttributes().get("userCertificate;binary").get();
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

                    String thumbprint = getThumbprint(cert);
                    logInfo("Evaluating certificate [SHA-1 Thumbprint: " + thumbprint + "] for encryption suitability.");

                    boolean[] keyUsage = cert.getKeyUsage();
                    if (keyUsage != null && keyUsage.length > 4 && keyUsage[4]) {
                        logInfo("Suitable encryption certificate found [SHA-1 Thumbprint: " + thumbprint + "].");
                        return cert;
                    } else {
                        logInfo("Rejected certificate [SHA-1: " + thumbprint + "] due to unsuitable key usage.");
                    }
                }
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "LDAP lookup failed: " + e.getMessage(), e);
                throw e;
            } finally {
                if (ctx != null) {
                    try {
                        ctx.close();
                    } catch (Exception ex) {
                        LOGGER.warning("Failed to close LDAP context: " + ex.getMessage());
                    }
                }
            }

            return null;
        }

        private static String getThumbprint(X509Certificate cert) throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        }
    }
}
