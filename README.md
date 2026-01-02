# Nuke: Time-Delayed Secure Deletion

[![Nuke Banner](https://img.shields.io/badge/Nuke-v3.3.0-red)](https://github.com/yourusername/nuke)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange)](https://www.rust-lang.org)

A secure file deletion tool that allows you to schedule files and folders for irreversible deletion at a specified future time. Once armed, files are encrypted with ChaCha20, and when the deadline arrives, they are permanently wiped with cryptographic verification.

## Features

- **Time-Delayed Deletion**: Schedule files for deletion at a specific future time
- **Secure Wiping**: Uses ChaCha20 encryption followed by secure deletion
- **Flexible Time Formats**: Support both absolute dates and relative durations
- **Daemon Mode**: Background service that monitors and deletes expired targets
- **Cryptographic Verification**: Ensures files are properly encrypted before deletion
- **Database Tracking**: SQLite database to track all armed targets
- **Progress Indicators**: Visual feedback for large file operations

## Installation

### From Source

```bash
git clone https://github.com/yourusername/nuke.git
cd nuke
cargo build --release
```

The binary will be available at `target/release/nuke`.

### Systemd Service (Optional)

To run nuke as a background service:

```bash
sudo cp nuke.service /etc/systemd/system/
sudo systemctl enable nuke
sudo systemctl start nuke
```

## Usage

### Basic Commands

#### Arm a file for deletion

```bash
# Delete file in 24 hours
nuke arm ./secret.txt 24h

# Delete folder at specific date
nuke arm ./sensitive-folder "2023-12-31 23:59:59"

# Delete with complex relative time
nuke arm ./data "4d-3h-30m"
```

#### List all armed targets

```bash
nuke list
```

#### Check status of a specific target

```bash
nuke status ./secret.txt
```

#### Disarm (cancel) a scheduled deletion

```bash
nuke disarm ./secret.txt
```

#### Immediate secure wipe (bypass scheduling)

```bash
nuke wipe ./temporary-file
```

#### Run the daemon

```bash
nuke daemon
```

### Time Formats

Nuke supports flexible time formats:

**Relative Durations:**
- `24h` - 24 hours
- `7d` - 7 days
- `2w` - 2 weeks
- `30m` - 30 minutes
- `4d-3h-30m` - 4 days, 3 hours, and 30 minutes
- `1h30m` - 1 hour and 30 minutes

**Absolute Dates:**
- `2023-12-31`
- `2023-12-31 23:59:59`
- `2023-12-31 23:59`

## Security

Nuke implements multiple layers of security:

1. **Encryption**: Files are encrypted using ChaCha20 stream cipher
2. **Key Zeroization**: Encryption keys are securely wiped from memory after use
3. **Verification**: Hash verification ensures files are properly encrypted
4. **Atomic Operations**: Temporary files are used to prevent data corruption
5. **Secure Deletion**: Files are overwritten before deletion

## How It Works

1. **Arming**: When you arm a file, it's added to an SQLite database with its deletion time
2. **Encryption**: At deletion time, files are encrypted with a random ChaCha20 key
3. **Verification**: The encrypted file is hashed and verified against the original
4. **Key Destruction**: Encryption keys are zeroized from memory
5. **Deletion**: The encrypted file is permanently removed from the filesystem

## Configuration

Nuke stores its database in your system's config directory:
- Linux: `~/.config/nuke/nuke.db`
- macOS: `~/Library/Application Support/nuke/nuke.db`
- Windows: `%APPDATA%\nuke\nuke.db`

## Requirements

- Rust 1.70 or higher
- SQLite (automatically handled by rusqlite)
- Linux, macOS, or Windows

## Warning

**IMPORTANT**: Nuke performs irreversible file deletion. Once a file is wiped, it cannot be recovered. Always double-check your targets before arming them.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Changelog

### v3.3.0
- Enhanced time parsing with humantime integration
- Improved daemon performance and reliability
- Better error messages and user feedback

### v3.1
- Added daemon mode for background operation
- Improved time parsing with more flexible formats
- Added progress indicators for large files
- Enhanced error handling and user feedback

### v2.1
- Initial release with core functionality
- ChaCha20 encryption implementation
- SQLite database for tracking targets