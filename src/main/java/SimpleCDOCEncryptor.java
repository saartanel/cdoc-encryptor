import org.openeid.cdoc4j.CDOCBuilder;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.naming.Context;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.io.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import javax.naming.NamingEnumeration;
import org.openeid.cdoc4j.DataFile;
import java.nio.file.Files;
import com.ctc.wstx.stax.WstxOutputFactory;
import javax.xml.stream.XMLOutputFactory;

public class SimpleCDOCEncryptor {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        if (args.length != 2) {
            System.out.println("Usage: java SimpleCDOCEncryptor <Estonian-ID-Code> <path-to-file>");
            return;
        }

        String personalIdCode = args[0];
        String filePath = args[1];

        File inputFile = new File(filePath);
        if (!inputFile.exists()) {
            throw new FileNotFoundException("Input file does not exist: " + filePath);
        }

        X509Certificate certificate = fetchCertificateFromLDAP(personalIdCode);
        if (certificate == null) {
            throw new Exception("Could not fetch certificate for ID: " + personalIdCode);
        }

        // Write cert to temp file
        File certFile = File.createTempFile("cert", ".cer");
        try (FileOutputStream fos = new FileOutputStream(certFile)) {
            fos.write(certificate.getEncoded());
        }

        // Configure XML processing explicitly
        XMLOutputFactory xmlOutputFactory = new WstxOutputFactory();
        System.setProperty("javax.xml.stream.XMLOutputFactory", 
                          xmlOutputFactory.getClass().getName());

        DataFile dataFile = new DataFile(
            inputFile.getName(),
            Files.readAllBytes(inputFile.toPath())
        );

        // Encrypt file with certificate using ID code as filename
        File outFile = new File(personalIdCode + ".cdoc");
        try {
            CDOCBuilder.defaultVersion()
                    .withDataFile(dataFile)
                    .withRecipient(certificate)
                    .buildToFile(outFile);  // Changed from build() to buildToFile()
        } finally {
            certFile.delete();
        }

        System.out.println("Encrypted file created at: " + outFile.getAbsolutePath());
    }

    private static X509Certificate fetchCertificateFromLDAP(String idCode) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldaps://esteid.ldap.sk.ee");
        env.put(Context.SECURITY_PROTOCOL, "ssl");

        LdapContext ctx = new InitialLdapContext(env, null);

        String base = "c=EE";
        // Modified filter to get encryption certificate
        String filter = "(&(objectClass=person)(serialNumber=PNOEE-" + idCode + "))";
        SearchControls sc = new SearchControls();
        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String[] attributeFilter = {"userCertificate;binary"};
        sc.setReturningAttributes(attributeFilter);

        NamingEnumeration<SearchResult> results = ctx.search(base, filter, sc);
        while (results.hasMore()) {
            SearchResult sr = results.next();
            byte[] certBytes = (byte[]) sr.getAttributes().get("userCertificate;binary").get();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
            
            // Check if this is the encryption certificate
            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage != null && keyUsage[4]) { // Index 4 is for keyAgreement
                return cert;
            }
        }
        return null;
    }
}