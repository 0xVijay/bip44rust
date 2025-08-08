 
## Development Rules Changes

### 1. Complete Implementation Principle
- **Change**: "RAII for all resources (memory, CUDA contexts, etc.)" → "RAII for all resources (memory, OpenCL contexts, etc.)"
- **Add**: "Use Rust's Drop trait for automatic resource cleanup"

### 2. Efficiency and Simplicity
- **Change**: "Fewer lines of code, the better" → "Leverage Rust's zero-cost abstractions"
- **Add**: "Use Rust's type system to prevent errors at compile time"

### 3. Senior Developer Approach
- **Add**: "Leverage Rust's ownership system for memory safety"
- **Add**: "Use Result<T, E> for comprehensive error handling"

### 4. No Code Duplication
- **Change**: "Library functions - Leverage existing libraries" → "Crate ecosystem - Use established Rust crates (ocl, secp256k1, sha2, etc.)"

### 5. Complete Function Implementation
- **Change**: "RAII for all resources (memory, CUDA contexts, etc.)" → "RAII for all resources (memory, OpenCL contexts, etc.)"
- **Add**: "Use Rust's Result<T, E> for error handling"

### 6. Documentation and Comments
- **Change**: "Explain complex cryptographic operations and CUDA optimizations" → "Explain complex cryptographic operations and OpenCL optimizations"

### 7. Testing and Validation
- **Add**: "Use Rust's built-in testing framework"
- **Add**: "Leverage Rust's type system for compile-time testing"

### 8. Performance Optimization
- **Change**: "Kernel optimization - Focus on occupancy, memory coalescing, and warp efficiency" → "Kernel optimization - Focus on work-group efficiency, memory coalescing, and device utilization"
- **Change**: "GPU memory optimization" → "OpenCL memory optimization"

### 9. Security Considerations
- **Add**: "Leverage Rust's memory safety guarantees"
- **Add**: "Use Rust's type system to prevent common vulnerabilities"

### 10. Build and Deployment
- **Change**: "CMake build system" → "Cargo build system"
- **Change**: "Use pnpm for dependency management" → "Use Cargo for dependency management"

## Quality Standards Changes

### Code Quality
- **Change**: "C++17/20 standards" → "Rust 2021 edition standards"
- **Add**: "Follow Rust naming conventions (snake_case for functions, PascalCase for types)"

### Performance Standards
- **Add**: "Leverage Rust's zero-cost abstractions for performance"
- **Add**: "Use async/await for non-blocking GPU operations"

### Testing Standards
- **Add**: "Use Rust's built-in testing framework"
- **Add**: "Leverage property-based testing with proptest"

### Documentation Standards
- **Add**: "Include Cargo.toml documentation"
- **Add**: "Document crate dependencies and versions"

## Focus Areas for Implementation

### Phase 1: Core Infrastructure
1. **Setup Rust/OpenCL Environment**
   - Configure Cargo.toml with dependencies
   - Set up OpenCL bindings with `ocl` crate
   - Create basic project structure

2. **Implement Basic Cryptographic Functions**
   - Use `secp256k1` crate for elliptic curve operations
   - Use `sha2` and `hmac` crates for hashing
   - Test with known seed phrases

3. **Create OpenCL Kernel Framework**
   - Set up OpenCL context and command queue
   - Implement basic kernel loading and execution
   - Test kernel compilation and execution

### Phase 2: GPU Acceleration
1. **Implement PBKDF2-HMAC-SHA512 Kernel**
   - Write OpenCL kernel for BIP39 seed derivation
   - Optimize for 2048 iterations
   - Test against CPU implementation

2. **Implement BIP44 Key Derivation**
   - Create OpenCL kernels for HMAC-SHA512
   - Implement secp256k1 operations on GPU
   - Test hierarchical derivation

3. **Implement Ethereum Address Generation**
   - Create Keccak-256 hashing kernel
   - Implement address extraction and formatting
   - Test address generation correctness

### Phase 3: Integration and Optimization
1. **Pipeline Integration**
   - Connect all kernels into unified pipeline
   - Implement async data flow
   - Test complete recovery process

2. **Multi-GPU Support**
   - Implement workload distribution
   - Create load balancing algorithms
   - Test scaling across multiple GPUs

3. **Performance Optimization**
   - Profile and optimize memory transfers
   - Tune kernel configurations
   - Implement batch processing

### Phase 4: Advanced Features
1. **Search Space Management**
   - Implement candidate generation
   - Create filtering algorithms
   - Optimize search strategies

2. **Monitoring and Control**
   - Create progress monitoring
   - Implement checkpoint/resume
   - Add performance metrics

3. **Robustness and Error Handling**
   - Implement comprehensive error handling
   - Add recovery mechanisms
   - Handle edge cases

Each phase should be completed and tested before moving to the next, ensuring a solid foundation for the subsequent development stages.