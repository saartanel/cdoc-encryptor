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

Run the program:
```bash
java -jar target/cdoc-encryptor-1.0-jar-with-dependencies.jar <Estonian-ID-Code> <path-to-file>
```

The encrypted file will be created as `<Estonian-ID-Code>.cdoc` in the current directory.

## Libraries Used

- cdoc4j 1.5
- Bouncy Castle 1.76
- Logback 1.4.11

## License

MIT License - See [LICENSE](LICENSE) file for details