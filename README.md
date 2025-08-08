# Ethereum BIP39 GPU Solver

A high-performance GPU-accelerated tool for recovering Ethereum seed phrases from partial information using OpenCL.

## Features

- 🚀 **GPU Acceleration**: Leverages OpenCL for massive parallel processing
- 🔐 **Ethereum Focus**: Specifically designed for Ethereum wallet recovery
- 📝 **BIP39 Compatible**: Full BIP39 mnemonic phrase support
- 🎯 **Partial Recovery**: Recover from word prefixes and target addresses
- ⚡ **High Performance**: Process millions of candidates per second
- 🔧 **Multi-GPU Support**: Automatically utilizes all available GPUs

## Requirements

- Rust 1.70+ with Cargo
- OpenCL-compatible GPU (NVIDIA, AMD, or Intel)
- OpenCL drivers and SDK installed

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd bip44cuda
```

2. Build the project:
```bash
cargo build --release
```

## Usage

### Basic Recovery

Recover a seed phrase using word prefixes and target Ethereum address:

```bash
cargo run --release -- recover \
  --target 0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b \
  --prefixes ab,cd,ef,gh,ij,kl,mn,op,qr,st,uv,wx
```

### With Custom Batch Size

```bash
cargo run --release -- recover \
  --target 0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b \
  --prefixes ab,cd,ef,gh,ij,kl,mn,op,qr,st,uv,wx \
  --batch-size 2048
```

### With Passphrase

```bash
cargo run --release -- recover \
  --target 0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b \
  --prefixes ab,cd,ef,gh,ij,kl,mn,op,qr,st,uv,wx \
  --passphrase "my secret passphrase"
```

## Command Line Options

- `--target <ADDRESS>`: Target Ethereum address to recover (required)
- `--prefixes <PREFIXES>`: Comma-separated list of 12 two-letter word prefixes
- `--batch-size <SIZE>`: Number of candidates to process per GPU batch (default: 1024)
- `--passphrase <PHRASE>`: BIP39 passphrase (default: empty)

## How It Works

1. **Candidate Generation**: Generates mnemonic candidates from word prefixes
2. **GPU Processing**: Uses OpenCL kernels to perform PBKDF2-HMAC-SHA512 on GPU
3. **Key Derivation**: Derives Ethereum private keys using BIP44 path `m/44'/60'/0'/0/0`
4. **Address Generation**: Generates Ethereum addresses using secp256k1 + Keccak256
5. **Verification**: Compares generated addresses with target address

## Performance

- **Modern GPU**: 1M+ candidates per second
- **Multi-GPU**: Linear scaling with additional GPUs
- **Memory Efficient**: Optimized for GPU memory constraints

## OpenCL Kernels

The project includes optimized OpenCL kernels in the `cl/` directory:

- `just_seed.cl`: PBKDF2-HMAC-SHA512 for seed generation
- `common.cl`: Common utilities and constants
- `sha2.cl`: SHA-256/SHA-512 implementations
- `mnemonic_constants.cl`: BIP39 word list constants

## Security Notes

- ⚠️ **Use Responsibly**: Only use this tool to recover your own wallets
- 🔒 **Private Keys**: Generated private keys are handled securely in memory
- 🛡️ **No Network**: Tool works completely offline for security

## Troubleshooting

### No GPU Devices Found

```bash
# Check OpenCL installation
clinfo

# Install OpenCL drivers for your GPU vendor
# NVIDIA: CUDA Toolkit
# AMD: ROCm or AMDGPU-PRO
# Intel: Intel OpenCL Runtime
```

### Compilation Errors

```bash
# Update Rust toolchain
rustup update

# Clean and rebuild
cargo clean
cargo build --release
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and legitimate wallet recovery purposes only. Users are responsible for ensuring they have the legal right to attempt recovery of any wallet addresses.