# CDOC File Encryptor

A simple Java program to encrypt files using Estonian ID card certificates.

## Prerequisites

- Java 11 or newer
- Maven 3.6 or newer
- Internet connection (for certificate lookup)
- Estonian ID code of the recipient

## Building

Build the project with Maven:
```bash
mvn clean package
```

This will create an executable JAR with all dependencies included.

## Usage

The program supports the following commands and flags:

### Commands

- `encrypt` - Encrypt a file for an Estonian ID card holder

### Required Flags

- `--id` - Estonian ID code of the recipient
- `--input-file` - Path to the file to be encrypted

### Optional Flags

- `-h, --help` - Show help message and exit
- `-V, --version` - Print version information and exit
- `--verbose` - Enable verbose logging

### Examples

Show help:
```bash
java -jar target/cdoc-encryptor-1.0-jar-with-dependencies.jar --help
```

Show command-specific help:
```bash
java -jar target/cdoc-encryptor-1.0-jar-with-dependencies.jar encrypt --help
```

Encrypt a file:
```bash
java -jar target/cdoc-encryptor-1.0-jar-with-dependencies.jar encrypt --id <Estonian-ID-Code> --input-file <path-to-file>
```

Encrypt with verbose logging:
```bash
java -jar target/cdoc-encryptor-1.0-jar-with-dependencies.jar encrypt --id <Estonian-ID-Code> --input-file <path-to-file> --verbose
```

The encrypted file will be created as `<Estonian-ID-Code>.cdoc` in the current directory.

## Technical Details

### SK LDAP Service

The program uses SK ID Solutions' LDAP service to fetch encryption certificates:
- LDAP URL: `ldaps://esteid.ldap.sk.ee`
- Base DN: `c=EE`
- Search filter: `(&(objectClass=person)(serialNumber=PNOEE-{idcode}))`
- Required attribute: `userCertificate;binary`

### CDOC Format

CDOC is an encrypted container format for secure file transfer. This program:
- Creates CDOC v1.1 containers (XML-based format)
- Uses recipients' public key certificates for encryption
- Implements AES-256-GCM for data encryption
- Uses ECDH for key transport

### Libraries Used

- cdoc4j 1.5 - CDOC container creation library
- Bouncy Castle 1.76 - Cryptographic operations
- Logback 1.4.11 - Logging framework

## References

- [SK LDAP Documentation](https://github.com/SK-EID/LDAP/wiki/Knowledge-Base)
- [CDOC4j Examples](https://github.com/open-eid/cdoc4j/wiki/Examples-of-how-to-use-it)
- [CDOC4j Source](https://github.com/open-eid/cdoc4j)

## License

MIT License - See [LICENSE](LICENSE) file for details