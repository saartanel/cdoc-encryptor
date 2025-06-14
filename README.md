# CDOC File Encryptor

A command-line Java application for encrypting files using Estonian ID card certificates. This tool securely encrypts files into CDOC containers that can be decrypted by Estonian ID card holders using their private keys.

## Features

- ✅ Encrypt files for any Estonian ID card holder
- ✅ Automatic certificate lookup via SK LDAP service
- ✅ CDOC 1.1 container format support
- ✅ Estonian ID code validation with checksum verification
- ✅ Certificate validation and expiry warnings
- ✅ Large file handling with progress indication
- ✅ Verbose logging for troubleshooting

## Prerequisites

- **Java 17 or newer** (Java 11+ may work but not tested)
- **Maven 3.6 or newer** (for building)
- **Internet connection** (for certificate lookup via LDAP)
- **Valid Estonian ID code** of the recipient

## Quick Start

### 1. Build the Application

```bash
git clone <repository-url>
cd cdoc-encryptor
mvn clean package
```

This creates an executable JAR: `target/cdoc-encryptor-1.0-shaded.jar`

### 2. Encrypt a File

```bash
java -jar target/cdoc-encryptor-1.0-shaded.jar encrypt \
  --id <Estonian-ID-Code> \
  --input-file document.pdf
```

The encrypted file will be saved as `<Estonian-ID-Code>.cdoc` in the current directory.

## Usage Reference

### Command Structure

```bash
java -jar cdoc-encryptor-1.0-shaded.jar encrypt [OPTIONS]
```

### Required Options

| Option | Description | Example |
|--------|-------------|---------|
| `--id` | Estonian ID code (11 digits) | `--id <Estonian-ID-Code>` |
| `--input-file`, `-i` | Path to file to encrypt | `-i document.pdf` |

### Optional Options

| Option | Description |
|--------|-------------|
| `--output-file`, `-o` | Custom output path (default: auto-generated) |
| `--verbose`, `-v` | Enable detailed logging |
| `--skip-cert-validation` | Skip certificate validation (not recommended) |
| `--help`, `-h` | Show help message |
| `--version`, `-V` | Show version information |

### Examples

**Basic encryption:**
```bash
java -jar cdoc-encryptor-1.0-shaded.jar encrypt --id <Estonian-ID-Code> -i contract.pdf
```

**With custom output file:**
```bash
java -jar cdoc-encryptor-1.0-shaded.jar encrypt \
  --id <Estonian-ID-Code> \
  --input-file contract.pdf \
  --output-file encrypted-contract.cdoc
```

**Verbose output for troubleshooting:**
```bash
java -jar cdoc-encryptor-1.0-shaded.jar encrypt \
  --id <Estonian-ID-Code> \
  -i document.pdf \
  --verbose
```

**Show help:**
```bash
java -jar cdoc-encryptor-1.0-shaded.jar --help
java -jar cdoc-encryptor-1.0-shaded.jar encrypt --help
```

## How It Works

### Certificate Lookup Process

1. **ID Validation**: Validates Estonian ID format and checksum
2. **LDAP Query**: Searches SK's LDAP service for certificates
3. **Certificate Selection**: Chooses authentication certificate for encryption
4. **Validation**: Checks certificate validity and expiration
5. **Encryption**: Creates CDOC container with AES-256-GCM encryption

### Estonian ID Card Certificates

Estonian ID cards contain two certificates:
- **Authentication certificate**: Used for encryption (this tool uses this one)
- **Signing certificate**: Used for digital signatures

The tool automatically selects the appropriate certificate for CDOC encryption.

## Technical Details

### LDAP Configuration
- **Server**: `ldaps://esteid.ldap.sk.ee`
- **Base DN**: `c=EE`
- **Search Filter**: `(&(objectClass=person)(serialNumber=PNOEE-{idcode}))`
- **Timeout**: 10 seconds for connection and read operations

### CDOC Format
- **Version**: CDOC 1.1 (XML-based)
- **Encryption**: AES-256-GCM for data encryption
- **Key Transport**: ECDH (Elliptic Curve Diffie-Hellman)
- **Container**: ZIP-based with XML metadata

### File Size Limits
- **Warning threshold**: Files over 100MB show performance warning
- **No hard limit**: Tool can handle large files (memory permitting)

## Troubleshooting

### Common Issues

**"Invalid Estonian ID format"**
- Ensure ID is exactly 11 digits
- Check that checksum is correct

**"Could not retrieve encryption certificate"**
- Verify the person has a valid Estonian ID card
- Check internet connection
- Try with `--verbose` flag for detailed error information

**"Certificate has expired"**
- The person's ID card certificate has expired
- They need to renew their ID card or certificate

**"Certificate expires in X days"**
- Warning that certificate expires soon
- Encryption will work but recipient should renew certificate

### Verbose Logging

Use the `--verbose` flag to see detailed information about:
- LDAP search process
- Certificate discovery and validation
- Encryption progress
- Error details and stack traces

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| cdoc4j | 1.5 | CDOC container creation |
| Bouncy Castle | 1.77 | Cryptographic operations |
| PicoCLI | 4.7.5 | Command-line interface |
| Logback | 1.4.14 | Logging framework |
| SLF4J | 2.0.9 | Logging API |

## Security Considerations

- **Certificate Validation**: Certificates are validated by default (can be disabled for testing)
- **Network Security**: Uses LDAPS (LDAP over TLS) for certificate lookup
- **No Private Keys**: Tool only handles public certificates, never private keys
- **Memory Safety**: Sensitive data cleared from memory after use

## Building from Source

### Requirements
- Java 17+ JDK
- Maven 3.6+

### Build Commands

```bash
# Clean build
mvn clean compile

# Run tests
mvn test

# Create executable JAR
mvn clean package

```

### Build Outputs

The build creates two JARs:
- `cdoc-encryptor-1.0.jar` - Basic JAR (requires classpath)
- `cdoc-encryptor-1.0-shaded.jar` - **Recommended** - All dependencies included

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## References

- [SK LDAP Documentation](https://github.com/SK-EID/LDAP/wiki/Knowledge-Base)
- [CDOC Format Specification](https://github.com/open-eid/cdoc4j/wiki)
- [Estonian ID Card Technical Specification](https://www.id.ee/en/article/for-developers/)
- [cdoc4j Library Examples](https://github.com/open-eid/cdoc4j/wiki/Examples-of-how-to-use-it)

## Support

For issues and questions:
- Check the troubleshooting section above
- Review verbose output with `--verbose` flag
- Open an issue on the project repository

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

*This tool is for legitimate use cases involving Estonian ID card encryption. Ensure you have proper authorization before encrypting files for others.*