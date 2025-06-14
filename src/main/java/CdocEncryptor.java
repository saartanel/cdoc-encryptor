package ee.saartanel.cdocencryptor;

import org.openeid.cdoc4j.CDOCBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.*;
import java.util.Hashtable;
import java.util.concurrent.Callable;
import java.util.regex.Pattern;

@Command(
    name = "cdoc-encryptor",
    description = "Encrypt files using Estonian ID card certificates",
    version = "1.0",
    mixinStandardHelpOptions = true
)
public class CdocEncryptor implements Callable<Integer> {
    
    private static final Logger logger = LoggerFactory.getLogger(CdocEncryptor.class);
    
    // LDAP configuration
    private static final String LDAP_URL = "ldaps://esteid.ldap.sk.ee";
    private static final String LDAP_BASE_DN = "c=EE";
    private static final String LDAP_SEARCH_FILTER = "(&(objectClass=person)(serialNumber=PNOEE-%s))";
    private static final String CERT_ATTRIBUTE = "userCertificate;binary";
    
    // Estonian ID validation pattern
    private static final Pattern ESTONIAN_ID_PATTERN = Pattern.compile("^[0-9]{11}$");
    
    @Command(name = "encrypt", description = "Encrypt a file for an Estonian ID card holder")
    static class EncryptCommand implements Callable<Integer> {
        
        @Option(names = {"--id"}, description = "Estonian ID code of the recipient (11 digits)", required = true)
        private String estonianId;
        
        @Option(names = {"--input-file", "-i"}, description = "Path to the file to be encrypted", required = true)
        private String inputFile;
        
        @Option(names = {"--output-file", "-o"}, description = "Output path for encrypted file (default: <id>.cdoc)")
        private String outputFile;
        
        @Option(names = {"--verbose", "-v"}, description = "Enable verbose logging")
        private boolean verbose;
        
        @Option(names = {"--skip-cert-validation"}, description = "Skip certificate validation (not recommended)")
        private boolean skipCertValidation;
        
        @Override
        public Integer call() throws Exception {
            configureLogging();
            
            // Validate Estonian ID format
            if (!isValidEstonianId(estonianId)) {
                logger.error("Invalid Estonian ID format.");
                return 1;
            }
            
            if (verbose) {
                logger.info("Starting encryption process");
            }
            
            try {
                // Validate input file
                Path inputPath = validateInputFile();
                if (inputPath == null) return 1;
                
                // Generate output path
                Path outputPath = generateOutputPath();
                
                // Fetch and validate certificate
                X509Certificate certificate = fetchAndValidateCertificate();
                if (certificate == null) return 1;
                
                // Encrypt the file
                return encryptFile(inputPath, outputPath, certificate);
                
            } catch (Exception e) {
                logger.error("Encryption failed: {}", e.getMessage());
                if (verbose) {
                    logger.error("Stack trace:", e);
                }
                return 1;
            }
        }
        
        private void configureLogging() {
            if (verbose) {
                System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
                System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
                System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "yyyy-MM-dd HH:mm:ss");
            }
        }
        
        private boolean isValidEstonianId(String id) {
            if (id == null || !ESTONIAN_ID_PATTERN.matcher(id).matches()) {
                return false;
            }
            
            // Basic checksum validation for Estonian ID
            return validateEstonianIdChecksum(id);
        }
        
        private boolean validateEstonianIdChecksum(String id) {
            try {
                int[] weights1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 1};
                int[] weights2 = {3, 4, 5, 6, 7, 8, 9, 1, 2, 3};
                
                int sum = 0;
                for (int i = 0; i < 10; i++) {
                    sum += Character.getNumericValue(id.charAt(i)) * weights1[i];
                }
                
                int checksum = sum % 11;
                if (checksum == 10) {
                    sum = 0;
                    for (int i = 0; i < 10; i++) {
                        sum += Character.getNumericValue(id.charAt(i)) * weights2[i];
                    }
                    checksum = sum % 11;
                    if (checksum == 10) checksum = 0;
                }
                
                return checksum == Character.getNumericValue(id.charAt(10));
            } catch (Exception e) {
                logger.debug("Checksum validation failed: {}", e.getMessage());
                return false;
            }
        }
        
        private Path validateInputFile() {
            Path inputPath = Paths.get(inputFile);
            
            if (!Files.exists(inputPath)) {
                logger.error("Input file not found: {}", inputFile);
                return null;
            }
            
            if (!Files.isReadable(inputPath)) {
                logger.error("Input file is not readable: {}", inputFile);
                return null;
            }
            
            if (Files.isDirectory(inputPath)) {
                logger.error("Input path is a directory, not a file: {}", inputFile);
                return null;
            }
            
            try {
                long fileSize = Files.size(inputPath);
                logger.debug("Input file size: {} bytes", fileSize);
                
                // Warn about large files
                if (fileSize > 100 * 1024 * 1024) { // 100MB
                    logger.warn("Large file detected ({}MB). Encryption may take some time.", 
                              fileSize / (1024 * 1024));
                }
            } catch (IOException e) {
                logger.warn("Could not determine file size: {}", e.getMessage());
            }
            
            return inputPath;
        }
        
        private Path generateOutputPath() {
            if (outputFile != null) {
                return Paths.get(outputFile);
            } else {
                return Paths.get(estonianId + ".cdoc");
            }
        }
        
        private X509Certificate fetchAndValidateCertificate() {
            try {
                if (verbose) {
                    logger.info("Fetching certificates from LDAP");
                }
                X509Certificate certificate = fetchEncryptionCertificateFromLDAP(estonianId);
                
                if (certificate == null) {
                    logger.error("Could not retrieve encryption certificate for the provided Estonian ID");
                    if (verbose) {
                        logger.info("Note: Make sure the person has a valid encryption certificate (not just authentication certificate)");
                    }
                    return null;
                }
                
                if (verbose) {
                    logger.info("Encryption certificate found. Subject: {}", certificate.getSubjectDN());
                    logger.debug("Certificate serial: {}", certificate.getSerialNumber());
                    logger.debug("Certificate valid from: {} to: {}", 
                               certificate.getNotBefore(), certificate.getNotAfter());
                }
                
                if (!skipCertValidation && !validateCertificate(certificate)) {
                    return null;
                }
                
                return certificate;
                
            } catch (Exception e) {
                logger.error("Failed to fetch or validate certificate: {}", e.getMessage());
                if (verbose) {
                    logger.error("Certificate error details:", e);
                }
                return null;
            }
        }
        
        private X509Certificate fetchEncryptionCertificateFromLDAP(String estonianId) throws NamingException, CertificateException {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, LDAP_URL);
            env.put(Context.SECURITY_PROTOCOL, "ssl");
            
            // Set connection timeouts
            env.put("com.sun.jndi.ldap.connect.timeout", "10000"); // 10 seconds
            env.put("com.sun.jndi.ldap.read.timeout", "10000");    // 10 seconds
            
            DirContext ctx = null;
            try {
                ctx = new InitialDirContext(env);
                
                SearchControls searchControls = new SearchControls();
                searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                searchControls.setReturningAttributes(new String[]{CERT_ATTRIBUTE});
                searchControls.setTimeLimit(10000); // 10 seconds
                
                String searchFilter = String.format(LDAP_SEARCH_FILTER, estonianId);
                logger.debug("LDAP search filter: {}", searchFilter);
                
                NamingEnumeration<SearchResult> results = ctx.search(LDAP_BASE_DN, searchFilter, searchControls);
                
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                X509Certificate authCert = null;
                X509Certificate signCert = null;
                int totalCertificatesFound = 0;
                
                // Process all LDAP entries - there will be separate entries for auth and signing certificates
                while (results.hasMore()) {
                    SearchResult result = results.next();
                    Attributes attributes = result.getAttributes();
                    Attribute certAttribute = attributes.get(CERT_ATTRIBUTE);
                    
                    String dn = result.getNameInNamespace();
                    logger.debug("Processing LDAP entry: {}", dn);
                    
                    if (certAttribute != null) {
                        for (int i = 0; i < certAttribute.size(); i++) {
                            totalCertificatesFound++;
                            byte[] certBytes = (byte[]) certAttribute.get(i);
                            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                                new java.io.ByteArrayInputStream(certBytes)
                            );
                            
                            logger.debug("Certificate {}: {}", totalCertificatesFound, cert.getSubjectX500Principal());
                            
                            // Determine certificate type based on DN and key usage
                            String certType = determineCertificateType(cert, dn);
                            logger.debug("Certificate {} type: {} (from DN: {})", totalCertificatesFound, certType, dn);
                            
                            if ("AUTHENTICATION".equals(certType)) {
                                authCert = cert;
                                if (verbose) {
                                    logger.info("Found authentication certificate from DN: {}", dn);
                                }
                            } else if ("SIGNING".equals(certType)) {
                                signCert = cert;
                                if (verbose) {
                                    logger.info("Found signing certificate from DN: {}", dn);
                                }
                            }
                        }
                    }
                }
                
                logger.debug("Total certificates found: {}", totalCertificatesFound);
                
                // For CDOC encryption, we need the authentication certificate
                if (authCert != null) {
                    if (verbose) {
                        logger.info("Using authentication certificate for encryption");
                    }
                    return authCert;
                } else if (signCert != null) {
                    logger.warn("Only signing certificate found, but authentication certificate needed for encryption");
                    if (verbose) {
                        logger.info("Attempting to use signing certificate anyway (may not work)");
                    }
                    return signCert;
                } else {
                    logger.error("No suitable certificates found among {} certificates", totalCertificatesFound);
                }
                
                return null;
                
            } finally {
                if (ctx != null) {
                    try {
                        ctx.close();
                    } catch (NamingException e) {
                        logger.warn("Failed to close LDAP context: {}", e.getMessage());
                    }
                }
            }
        }
        
        private String determineCertificateType(X509Certificate certificate, String dn) {
            try {
                // First, check the DN - Estonian ID cards have separate OUs for different certificate types
                if (dn != null) {
                    String dnUpper = dn.toUpperCase();
                    if (dnUpper.contains("OU=AUTHENTICATION")) {
                        logger.debug("Certificate identified as AUTHENTICATION based on DN");
                        return "AUTHENTICATION";
                    } else if (dnUpper.contains("OU=DIGITAL SIGNATURE")) {
                        logger.debug("Certificate identified as SIGNING based on DN");
                        return "SIGNING";
                    }
                }
                
                // Fallback to key usage analysis if DN doesn't give clear indication
                String subject = certificate.getSubjectDN().getName().toUpperCase();
                
                // Check subject DN for Estonian ID card certificate patterns
                if (subject.contains("DIGITAL SIGNATURE") || subject.contains("SIGNING")) {
                    return "SIGNING";
                }
                
                // Check key usage
                boolean[] keyUsage = certificate.getKeyUsage();
                if (keyUsage != null) {
                    boolean hasDigitalSignature = keyUsage.length > 0 && keyUsage[0]; // digitalSignature
                    boolean hasNonRepudiation = keyUsage.length > 1 && keyUsage[1];   // nonRepudiation
                    boolean hasKeyEncipherment = keyUsage.length > 2 && keyUsage[2];  // keyEncipherment
                    boolean hasDataEncipherment = keyUsage.length > 3 && keyUsage[3]; // dataEncipherment
                    boolean hasKeyAgreement = keyUsage.length > 4 && keyUsage[4];     // keyAgreement
                    
                    logger.debug("Key usage - digitalSignature: {}, nonRepudiation: {}, keyEncipherment: {}, dataEncipherment: {}, keyAgreement: {}", 
                               hasDigitalSignature, hasNonRepudiation, hasKeyEncipherment, hasDataEncipherment, hasKeyAgreement);
                    
                    // Estonian signing certificates typically have digitalSignature and nonRepudiation
                    // Estonian authentication certificates typically have keyAgreement for ECDH
                    if (hasNonRepudiation && hasDigitalSignature && !hasKeyAgreement) {
                        return "SIGNING";
                    } else if (hasKeyAgreement || hasKeyEncipherment) {
                        return "AUTHENTICATION"; // This one can be used for encryption
                    } else if (hasDigitalSignature && !hasNonRepudiation) {
                        return "AUTHENTICATION"; // Authentication certs can also have digitalSignature
                    }
                }
                
                // Check extended key usage
                try {
                    if (certificate.getExtendedKeyUsage() != null) {
                        for (String oid : certificate.getExtendedKeyUsage()) {
                            logger.debug("Extended key usage OID: {}", oid);
                            // 1.3.6.1.5.5.7.3.2 = Client Authentication
                            // 1.3.6.1.5.5.7.3.4 = Email Protection (encryption)
                            if ("1.3.6.1.5.5.7.3.2".equals(oid) || "1.3.6.1.5.5.7.3.4".equals(oid)) {
                                return "AUTHENTICATION";
                            }
                        }
                    }
                } catch (Exception e) {
                    logger.debug("Could not check extended key usage: {}", e.getMessage());
                }
                
                // Default assumption: if we can't determine, assume it's authentication
                return "AUTHENTICATION";
                
            } catch (Exception e) {
                logger.debug("Error determining certificate type: {}", e.getMessage());
                return "UNKNOWN";
            }
        }
        
        private boolean isCertificateSuitableForEncryption(X509Certificate certificate) {
            try {
                // For Estonian ID cards, the authentication certificate is used for encryption
                // It should have keyAgreement capability for ECDH key agreement
                
                boolean[] keyUsage = certificate.getKeyUsage();
                if (keyUsage != null) {
                    boolean hasKeyAgreement = keyUsage.length > 4 && keyUsage[4];
                    boolean hasKeyEncipherment = keyUsage.length > 2 && keyUsage[2];
                    boolean hasDataEncipherment = keyUsage.length > 3 && keyUsage[3];
                    
                    logger.debug("Key usage - keyAgreement: {}, keyEncipherment: {}, dataEncipherment: {}", 
                               hasKeyAgreement, hasKeyEncipherment, hasDataEncipherment);
                    
                    // For CDOC with Estonian ID cards, we primarily need keyAgreement
                    if (hasKeyAgreement) {
                        return true;
                    }
                    
                    // Some older cards might use keyEncipherment
                    if (hasKeyEncipherment || hasDataEncipherment) {
                        return true;
                    }
                }
                
                // If no specific key usage is set, it might still work
                // (some certificates don't have key usage extension)
                if (keyUsage == null) {
                    logger.debug("No key usage extension found, assuming certificate can be used for encryption");
                    return true;
                }
                
                return false;
                
            } catch (Exception e) {
                logger.debug("Error checking certificate suitability: {}", e.getMessage());
                return false;
            }
        }
        
        private boolean validateCertificate(X509Certificate certificate) {
            try {
                // Check if certificate is currently valid
                certificate.checkValidity();
                logger.debug("Certificate is currently valid");
                
                // Check if certificate will expire soon (within 30 days)
                long timeUntilExpiry = certificate.getNotAfter().getTime() - System.currentTimeMillis();
                long daysUntilExpiry = timeUntilExpiry / (1000 * 60 * 60 * 24);
                
                if (daysUntilExpiry < 30) {
                    logger.warn("Certificate expires in {} days: {}", daysUntilExpiry, certificate.getNotAfter());
                }
                
                // For Estonian ID cards used with CDOC, we need to be more flexible
                // The authentication certificate should work for encryption
                if (!isCertificateSuitableForEncryption(certificate)) {
                    logger.warn("Certificate may not be suitable for encryption, but proceeding anyway");
                    if (verbose) {
                        logger.info("Note: Estonian authentication certificates should work for CDOC encryption");
                    }
                }
                
                return true;
                
            } catch (CertificateExpiredException e) {
                logger.error("Certificate has expired: {}", certificate.getNotAfter());
                return false;
            } catch (CertificateNotYetValidException e) {
                logger.error("Certificate is not yet valid: {}", certificate.getNotBefore());
                return false;
            } catch (Exception e) {
                logger.error("Certificate validation failed: {}", e.getMessage());
                return false;
            }
        }
        
        private Integer encryptFile(Path inputPath, Path outputPath, X509Certificate certificate) {
            System.out.println("Encrypting " + inputPath.getFileName() + " -> " + outputPath.getFileName());
            
            try {
                // Check if output file already exists
                if (Files.exists(outputPath)) {
                    logger.warn("Output file already exists and will be overwritten: {}", outputPath);
                }
                
                // Create CDOC container using cdoc4j
                // Convert X509Certificate to InputStream for the API
                byte[] certBytes = certificate.getEncoded();
                java.io.ByteArrayInputStream certInputStream = new java.io.ByteArrayInputStream(certBytes);
                
                CDOCBuilder.defaultVersion() // Uses CDOC 1.1 by default
                    .withDataFile(inputPath.toFile())
                    .withRecipient(certInputStream)
                    .buildToFile(outputPath.toFile());
                
                System.out.println("File encrypted successfully: " + outputPath);
                
                // Verify output file was created and has content
                if (Files.exists(outputPath) && Files.size(outputPath) > 0) {
                    if (verbose) {
                        logger.info("Output file size: {} bytes", Files.size(outputPath));
                    }
                    return 0;
                } else {
                    logger.error("Output file was not created properly");
                    return 1;
                }
                
            } catch (CertificateEncodingException e) {
                logger.error("Failed to encode certificate: {}", e.getMessage());
                return 1;
            } catch (IOException e) {
                logger.error("File I/O error during encryption: {}", e.getMessage());
                return 1;
            } catch (Exception e) {
                logger.error("Unexpected error during encryption: {}", e.getMessage());
                if (verbose) {
                    logger.error("Encryption error details:", e);
                }
                return 1;
            }
        }
    }
    
    @Override
    public Integer call() throws Exception {
        // Show help when no subcommand is provided
        CommandLine.usage(this, System.out);
        return 0;
    }
    
    public static void main(String[] args) {
        CommandLine cmd = new CommandLine(new CdocEncryptor());
        cmd.addSubcommand("encrypt", new EncryptCommand());
        
        // Configure command line parsing
        cmd.setUsageHelpWidth(120);
        cmd.setAbbreviatedOptionsAllowed(true);
        
        try {
            int exitCode = cmd.execute(args);
            System.exit(exitCode);
        } catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            System.exit(1);
        }
    }
}