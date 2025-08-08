# Ethereum Seed Recovery Tool

A high-performance Rust/OpenCL application for recovering Ethereum seed phrases from partial information using GPU acceleration.

## Features

- **GPU Acceleration**: Leverages OpenCL for massive parallel processing on GPUs
- **Flexible Input**: Supports word constraints for each position in the seed phrase
- **BIP39/BIP44 Compliant**: Full implementation of BIP39 mnemonic generation and BIP44 hierarchical deterministic wallets
- **Ethereum Support**: Native Ethereum address generation with EIP-55 checksum
- **Progress Monitoring**: Real-time progress tracking with performance metrics
- **Checkpoint/Resume**: Save progress and resume interrupted recovery sessions
- **Multi-GPU Support**: Distribute workload across multiple GPUs
- **CPU Fallback**: Automatic fallback to CPU processing if GPU fails

## Requirements

### System Requirements
- **Operating System**: macOS, Linux, or Windows
- **Memory**: Minimum 8GB RAM (16GB+ recommended for large search spaces)
- **Storage**: At least 1GB free space for checkpoints and results

### GPU Requirements (Optional but Recommended)
- **OpenCL 1.2+** compatible GPU
- **VRAM**: Minimum 2GB (4GB+ recommended)
- **Supported GPUs**:
  - NVIDIA: GTX 1060 or newer
  - AMD: RX 580 or newer
  - Intel: Iris Pro or newer

### Software Dependencies
- **Rust**: 1.70.0 or newer
- **OpenCL SDK**: Platform-specific OpenCL development libraries

## Installation

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. Install OpenCL SDK

#### macOS
```bash
# OpenCL is included with macOS
# No additional installation required
```

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install opencl-headers ocl-icd-opencl-dev

# For NVIDIA GPUs
sudo apt install nvidia-opencl-dev

# For AMD GPUs
sudo apt install mesa-opencl-icd
```

#### Windows
- Install GPU vendor-specific drivers (NVIDIA/AMD)
- Download and install Intel OpenCL SDK or vendor-specific OpenCL SDK

### 3. Clone and Build

```bash
git clone <repository-url>
cd ethereum-seed-recovery
cargo build --release
```

## Configuration

Create a JSON configuration file with your recovery parameters:

```json
{
  "word_constraints": [
    { "position": 0, "words": ["fox", "field", "flame", "family", "frequent"] },
    { "position": 1, "words": ["lamp", "lava", "loop", "lunar", "lunch"] },
    { "position": 2, "words": ["iron", "item", "issue", "inch", "index"] },
    { "position": 3, "words": ["vivid", "vacuum", "valley", "verify"] },
    { "position": 4, "words": ["equal", "erase", "elegant", "engineer"] },
    { "position": 5, "words": ["dust", "double", "dolphin", "dream"] },
    { "position": 6, "words": ["hill", "hammer", "hazard", "hotel"] },
    { "position": 7, "words": ["glove", "grain", "giant", "guitar"] },
    { "position": 8, "words": ["paint", "parrot", "panic", "peach"] },
    { "position": 9, "words": ["yawn", "year", "yellow", "young"] },
    { "position": 10, "words": ["road", "rise", "ring", "run"] },
    { "position": 11, "words": ["arrow", "asset", "attic", "armor"] }
  ],
  "ethereum": {
    "derivation_path": "m/44'/60'/0'/0/2",
    "target_address": "0x543Bd35F52147370C0deCBd440863bc2a002C5c5",
    "passphrase": ""
  },
  "mnemonic_length": 12,
  "wallet_type": "ethereum",
  "batch_size": 10000,
  "num_threads": 8,
  "use_gpu": true,
  "max_memory_mb": 4096
}
```

### Configuration Parameters

- **word_constraints**: Array of possible words for each position
- **ethereum.derivation_path**: BIP44 derivation path (default: "m/44'/60'/0'/0/0")
- **ethereum.target_address**: Target Ethereum address to recover
- **ethereum.passphrase**: BIP39 passphrase (empty string if none)
- **mnemonic_length**: Number of words in seed phrase (12, 15, 18, 21, or 24)
- **wallet_type**: Wallet type (currently only "ethereum" supported)
- **batch_size**: Number of candidates to process in each batch
- **num_threads**: Number of CPU threads to use
- **use_gpu**: Enable GPU acceleration
- **max_memory_mb**: Maximum memory usage in MB

## Usage

### Basic Usage

```bash
# Run recovery with configuration file
./target/release/eth-seed-recovery -c config.json

# Specify output file
./target/release/eth-seed-recovery -c config.json -o results.json

# Enable verbose logging
./target/release/eth-seed-recovery -c config.json -v
```

### Advanced Usage

```bash
# Perform dry run to test configuration
./target/release/eth-seed-recovery -c config.json --dry-run

# Resume from checkpoint
./target/release/eth-seed-recovery -c config.json --resume

# Custom checkpoint file
./target/release/eth-seed-recovery -c config.json --checkpoint my_checkpoint.json
```

### Command Line Options

- `-c, --config <FILE>`: Configuration file path (required)
- `-o, --output <FILE>`: Output file for results (default: recovery_results.json)
- `--checkpoint <FILE>`: Checkpoint file for resuming (default: recovery_checkpoint.json)
- `--resume`: Resume from checkpoint
- `--dry-run`: Perform validation without actual recovery
- `-v, --verbose`: Enable verbose logging
- `-h, --help`: Show help information

## Performance Optimization

### GPU Optimization

1. **Batch Size**: Increase batch size for better GPU utilization
   ```json
   "batch_size": 50000  // For high-end GPUs
   ```

2. **Memory Usage**: Allocate more memory for larger batches
   ```json
   "max_memory_mb": 8192  // For GPUs with 8GB+ VRAM
   ```

3. **Multiple GPUs**: The tool automatically detects and uses multiple GPUs

### CPU Optimization

1. **Thread Count**: Set to number of CPU cores
   ```json
   "num_threads": 16  // For 16-core CPU
   ```

2. **Batch Size**: Smaller batches for CPU processing
   ```json
   "batch_size": 1000  // For CPU-only processing
   ```

## Expected Performance

### GPU Performance (RTX 3080)
- **Batch Processing**: ~1M candidates/second
- **Memory Usage**: ~2-4GB VRAM
- **Power Consumption**: ~250W

### CPU Performance (16-core)
- **Batch Processing**: ~50K candidates/second
- **Memory Usage**: ~1-2GB RAM
- **Power Consumption**: ~100W

## Search Space Estimation

The tool automatically calculates the search space based on word constraints:

```
Search Space = Π(number of words for each position)

Example:
- Position 0: 5 words
- Position 1: 5 words
- ...
- Position 11: 4 words

Total = 5 × 5 × 5 × 4 × 4 × 4 × 4 × 4 × 5 × 4 × 4 × 4 = 1,638,400,000 combinations
```

## Security Considerations

1. **Private Key Security**: Private keys are only stored in memory temporarily
2. **Result Storage**: Results are saved to local files - ensure proper file permissions
3. **Network Security**: Tool operates offline - no network communication
4. **Memory Cleanup**: Sensitive data is cleared from memory after use

## Troubleshooting

### OpenCL Issues

```bash
# Check OpenCL installation
clinfo

# Test with dry run
./target/release/eth-seed-recovery -c config.json --dry-run
```

### Memory Issues

```bash
# Reduce batch size
"batch_size": 1000

# Reduce memory limit
"max_memory_mb": 2048
```

### Performance Issues

```bash
# Enable verbose logging to identify bottlenecks
./target/release/eth-seed-recovery -c config.json -v

# Monitor system resources
top -p $(pgrep eth-seed-recovery)
```

## Example Results

### Successful Recovery

```json
{
  "success": true,
  "mnemonic": "fox lamp iron vivid equal dust hill glove paint yawn road arrow",
  "target_address": "0x543Bd35F52147370C0deCBd440863bc2a002C5c5",
  "derivation_path": "m/44'/60'/0'/0/2",
  "timestamp": "2024-01-15T10:30:45Z",
  "performance": {
    "total_candidates_processed": 1234567,
    "processing_time_seconds": 3600,
    "candidates_per_second": 343.0,
    "memory_usage_mb": 2048.5
  }
}
```

### Failed Recovery

```json
{
  "success": false,
  "message": "No matching seed phrase found",
  "target_address": "0x543Bd35F52147370C0deCBd440863bc2a002C5c5",
  "derivation_path": "m/44'/60'/0'/0/2",
  "timestamp": "2024-01-15T12:30:45Z",
  "performance": {
    "total_candidates_processed": 1638400000,
    "processing_time_seconds": 14400,
    "candidates_per_second": 113777.8,
    "memory_usage_mb": 4096.0
  }
}
```

## Development

### Building from Source

```bash
# Debug build
cargo build

# Release build with optimizations
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- -c config.json
```

### Project Structure

```
src/
├── main.rs              # Main application entry point
├── lib.rs               # Library root
├── config.rs            # Configuration management
├── crypto.rs            # BIP39/BIP44 cryptographic functions
├── ethereum.rs          # Ethereum address generation
├── generator.rs         # Candidate generation
├── monitor.rs           # Progress monitoring
├── opencl.rs            # OpenCL GPU acceleration
├── error.rs             # Error types and handling
└── kernels/             # OpenCL kernel files
    ├── pbkdf2.cl         # PBKDF2-HMAC-SHA512 kernel
    ├── hmac.cl           # HMAC-SHA512 kernel
    ├── secp256k1.cl      # secp256k1 operations kernel
    └── keccak.cl         # Keccak-256 kernel
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

**Important**: This tool is for educational and legitimate recovery purposes only. Users are responsible for:

- Ensuring they have legal rights to recover the seed phrases
- Complying with local laws and regulations
- Securing recovered private keys and seed phrases
- Understanding the risks involved in cryptocurrency recovery

The authors are not responsible for any misuse of this tool or any financial losses.

## Support

For issues, questions, or contributions:

1. Check existing GitHub issues
2. Create a new issue with detailed information
3. Include system information and error logs
4. Provide minimal reproduction steps

## Acknowledgments

- **BIP39/BIP44 Standards**: Bitcoin Improvement Proposals
- **Rust Ecosystem**: Amazing crates that made this possible
- **OpenCL Community**: For GPU computing standards
- **Ethereum Foundation**: For Ethereum specifications