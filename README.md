# CDOC File Encryptor

A command-line Java application for encrypting files using Estonian ID card certificates. This tool securely encrypts files into CDOC containers that can be decrypted by Estonian ID card holders using their private keys.

## Features

- Encrypt files for any Estonian ID card holder
- Automatic certificate lookup via SK LDAP service
- CDOC 1.1 container format support
- Estonian ID code validation with checksum verification
- Certificate validation and expiry warnings
- Large file handling with progress indication
- Verbose logging for troubleshooting

## Prerequisites

- **Java 17 or newer** (Java 11+ may work but not tested)
- **Maven 3.6 or newer** (for building from source)
- **Internet connection** (for certificate lookup via LDAP)
- **Valid Estonian ID code** of the recipient

## Usage

### Basic Command Structure
```bash
java -jar cdoc-encryptor-1.0-jar-with-dependencies.jar encrypt [OPTIONS]
```

### Required Parameters
- `--id <Estonian-ID-Code>` - 11-digit Estonian ID code
- `--input-file <path>` or `-i <path>` - File to encrypt

### Optional Parameters
- `--output-file <path>` or `-o <path>` - Custom output path (default: auto-generated)
- `--verbose` or `-v` - Enable detailed logging
- `--skip-cert-validation` - Skip certificate validation (not recommended)
- `--help` or `-h` - Show help message
- `--version` or `-V` - Show version information

### Examples

**Basic encryption:**
```bash
java -jar cdoc-encryptor-1.0-jar-with-dependencies.jar encrypt --id <Estonian-ID-Code> -i contract.pdf
```

**Custom output file:**
```bash
java -jar cdoc-encryptor-1.0-jar-with-dependencies.jar encrypt \
  --id <Estonian-ID-Code> \
  --input-file contract.pdf \
  --output-file encrypted-contract.cdoc
```

**Verbose output for troubleshooting:**
```bash
java -jar cdoc-encryptor-1.0-jar-with-dependencies.jar encrypt \
  --id <Estonian-ID-Code> -i document.pdf --verbose
```

## How It Works

The tool follows this process:

1. **ID Validation** - Validates Estonian ID format and checksum
2. **Certificate Lookup** - Searches SK's LDAP service for the person's certificates
3. **Certificate Selection** - Automatically selects the authentication certificate
4. **Validation** - Checks certificate validity and warns about expiration
5. **Encryption** - Creates a CDOC container with AES-256-GCM encryption

The encrypted file is saved as `<Estonian-ID-Code>.cdoc` (or your custom filename).

## Troubleshooting

### Common Issues

**"Invalid Estonian ID format"**
- Ensure ID is exactly 11 digits with correct checksum

**"Could not retrieve encryption certificate"**
- Verify the person has a valid Estonian ID card
- Check internet connection
- Try with `--verbose` flag for detailed error information

**"Certificate has expired"**
- The person's ID card certificate has expired and needs renewal

**"Certificate expires in X days"**
- Warning that certificate expires soon (encryption still works)

### Getting More Information

Use the `--verbose` flag to see detailed information about:
- LDAP search process
- Certificate discovery and validation
- Encryption progress
- Error details and stack traces

## Technical Details

### LDAP Configuration
- **Server**: `ldaps://esteid.ldap.sk.ee`
- **Search**: Finds certificates by Estonian ID code
- **Timeout**: 10 seconds for connection and read operations

### CDOC Format
- **Version**: CDOC 1.1 (XML-based container)
- **Encryption**: AES-256-GCM for data encryption
- **Key Transport**: ECDH (Elliptic Curve Diffie-Hellman)
- **Structure**: ZIP-based with XML metadata

### File Handling
- **Warning**: Files over 100MB show performance warning
- **No hard limit**: Can handle large files (memory permitting)

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| cdoc4j | 1.5 | CDOC container creation |
| Bouncy Castle | 1.77 | Cryptographic operations |
| PicoCLI | 4.7.5 | Command-line interface |
| Logback | 1.4.14 | Logging framework |

## Security

- **Certificate Validation**: Certificates validated by default
- **Network Security**: Uses LDAPS (LDAP over TLS)
- **No Private Keys**: Only handles public certificates
- **Memory Safety**: Sensitive data cleared after use

## Building from Source

### Requirements
- Java 17+ JDK
- Maven 3.6+

### Commands
```bash
# Clean build
mvn clean compile

# Run tests
mvn test

# Create executable JAR
mvn clean package
```

### Build Outputs
- `target/cdoc-encryptor-1.0.jar` - Basic JAR (requires classpath)
- `target/cdoc-encryptor-1.0-jar-with-dependencies.jar` - **Recommended** (all dependencies included)

## References

- [SK LDAP Documentation](https://github.com/SK-EID/LDAP/wiki/Knowledge-Base)
- [CDOC Format Specification](https://github.com/open-eid/cdoc4j/wiki)
- [Estonian ID Card Technical Specification](https://www.id.ee/en/article/for-developers/)
- [cdoc4j Library Examples](https://github.com/open-eid/cdoc4j/wiki/Examples-of-how-to-use-it)

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

*This tool is for legitimate use cases involving Estonian ID card encryption. Ensure you have proper authorization before encrypting files for others.*
