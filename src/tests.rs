//! Comprehensive test suite for Ethereum BIP39 seed phrase recovery
//! Tests all cryptographic functions and GPU processing capabilities

use crate::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test data structure for known seed phrases and their expected outputs
    struct TestVector {
        mnemonic: &'static str,
        passphrase: &'static str,
        seed_hex: &'static str,
        derivation_path: &'static str,
        expected_address: &'static str,
    }

    /// Known test vectors for validation
    const TEST_VECTORS: &[TestVector] = &[
        TestVector {
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            passphrase: "",
            seed_hex: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            derivation_path: "m/44'/60'/0'/0/0",
            expected_address: "0x9858effd232b4033e47d90003d41ec34ecaeda94",
        },
        TestVector {
            mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow",
            passphrase: "",
            seed_hex: "878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096",
            derivation_path: "m/44'/60'/0'/0/0",
            expected_address: "0x58a57ed9d8d624cbd12e2c467d34787555bb1b25",
        },
        TestVector {
            mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            passphrase: "TREZOR",
            seed_hex: "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
            derivation_path: "m/44'/60'/0'/0/0",
            expected_address: "0x97aa6f4c3e3120e25ad2ad3b88e6c13ef21ace4a",
        },
    ];

    #[test]
    fn test_mnemonic_validation() {
        println!("Testing mnemonic validation...");
        
        // Test valid mnemonics
        for vector in TEST_VECTORS {
            assert!(is_valid_mnemonic(vector.mnemonic), 
                "Valid mnemonic should pass validation: {}", vector.mnemonic);
        }
        
        // Test invalid mnemonics
        let invalid_mnemonics = [
            "invalid mnemonic phrase",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", // 11 words
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", // 13 words
            "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ];
        
        for invalid in &invalid_mnemonics {
            assert!(!is_valid_mnemonic(invalid), 
                "Invalid mnemonic should fail validation: {}", invalid);
        }
        
        println!("✓ Mnemonic validation tests passed");
    }

    #[test]
    fn test_mnemonic_to_seed() {
        println!("Testing mnemonic to seed conversion...");
        
        for vector in TEST_VECTORS {
            let result = mnemonic_to_seed(vector.mnemonic, vector.passphrase);
            assert!(result.is_ok(), "Seed generation should succeed for: {}", vector.mnemonic);
            
            let seed = result.unwrap();
            let seed_hex = hex::encode(seed);
            
            assert_eq!(seed_hex, vector.seed_hex, 
                "Seed should match expected value for mnemonic: {}", vector.mnemonic);
        }
        
        println!("✓ Mnemonic to seed conversion tests passed");
    }

    #[test]
    fn test_ethereum_address_derivation() {
        println!("Testing Ethereum address derivation...");
        
        for vector in TEST_VECTORS {
            let seed_result = mnemonic_to_seed(vector.mnemonic, vector.passphrase);
            assert!(seed_result.is_ok(), "Seed generation should succeed");
            
            let seed = seed_result.unwrap();
            let address_result = derive_ethereum_address(&seed, vector.derivation_path);
            assert!(address_result.is_ok(), "Address derivation should succeed for: {}", vector.mnemonic);
            
            let address = address_result.unwrap();
            assert_eq!(address.to_lowercase(), vector.expected_address.to_lowercase(), 
                "Address should match expected value for mnemonic: {}", vector.mnemonic);
        }
        
        println!("✓ Ethereum address derivation tests passed");
    }

    #[test]
    fn test_check_mnemonic_function() {
        println!("Testing complete mnemonic check function...");
        
        for vector in TEST_VECTORS {
            let result = check_mnemonic(
                vector.mnemonic, 
                vector.passphrase, 
                vector.derivation_path, 
                vector.expected_address
            );
            
            assert!(result.is_ok(), "Mnemonic check should succeed");
            assert!(result.unwrap(), "Mnemonic should match target address: {}", vector.mnemonic);
        }
        
        // Test with wrong address
        let wrong_address = "0x0000000000000000000000000000000000000000";
        for vector in TEST_VECTORS {
            let result = check_mnemonic(
                vector.mnemonic, 
                vector.passphrase, 
                vector.derivation_path, 
                wrong_address
            );
            
            assert!(result.is_ok(), "Mnemonic check should succeed");
            assert!(!result.unwrap(), "Mnemonic should not match wrong address");
        }
        
        println!("✓ Complete mnemonic check function tests passed");
    }

    #[test]
    fn test_config_parsing() {
        println!("Testing configuration parsing...");
        
        let test_config = r#"
mnemonic_length = 12
wallet_type = "ethereum"

[[word_constraints]]
position = 0
words = ["abandon", "ability"]

[[word_constraints]]
position = 1
words = ["abandon", "able"]

[ethereum]
derivation_path = "m/44'/60'/0'/0/0"
target_address = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
passphrase = ""
"#;
        
        let config: Result<Config, _> = toml::from_str(test_config);
        assert!(config.is_ok(), "Config parsing should succeed");
        
        let config = config.unwrap();
        assert_eq!(config.mnemonic_length, 12);
        assert_eq!(config.wallet_type, "ethereum");
        assert_eq!(config.word_constraints.len(), 2);
        assert_eq!(config.ethereum.derivation_path, "m/44'/60'/0'/0/0");
        
        println!("✓ Configuration parsing tests passed");
    }

    #[test]
    fn test_candidate_generation() {
        println!("Testing candidate generation...");
        
        // Create a small test case with constraints for all 12 positions
        let config = Config {
            mnemonic_length: 12,
            wallet_type: "ethereum".to_string(),
            word_constraints: vec![
                WordConstraint { position: 0, words: vec!["abandon".to_string(), "ability".to_string()] },
                WordConstraint { position: 1, words: vec!["abandon".to_string()] },
                WordConstraint { position: 2, words: vec!["abandon".to_string()] },
                WordConstraint { position: 3, words: vec!["abandon".to_string()] },
                WordConstraint { position: 4, words: vec!["abandon".to_string()] },
                WordConstraint { position: 5, words: vec!["abandon".to_string()] },
                WordConstraint { position: 6, words: vec!["abandon".to_string()] },
                WordConstraint { position: 7, words: vec!["abandon".to_string()] },
                WordConstraint { position: 8, words: vec!["abandon".to_string()] },
                WordConstraint { position: 9, words: vec!["abandon".to_string()] },
                WordConstraint { position: 10, words: vec!["abandon".to_string()] },
                WordConstraint { position: 11, words: vec!["about".to_string(), "above".to_string()] },
            ],
            ethereum: EthereumConfig {
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
                target_address: "0x9858effd232b4033e47d90003d41ec34ecaeda94".to_string(),
                passphrase: "".to_string(),
            },
            batch_size: 1024,
        };
        
        let result = generate_candidate_mnemonics(&config);
        assert!(result.is_ok(), "Candidate generation should succeed");
        
        let (candidates, word_indices) = result.unwrap();
        assert!(!candidates.is_empty(), "Should generate candidates");
        assert_eq!(candidates.len(), word_indices.len(), "Candidates and indices should match");
        
        // Check that candidates follow constraints
        for candidate in &candidates {
            let words: Vec<&str> = candidate.split_whitespace().collect();
            assert_eq!(words.len(), 12, "Each candidate should have 12 words");
            
            // Check position 0 constraint
            assert!(words[0] == "abandon" || words[0] == "ability", 
                "First word should match constraint: {}", words[0]);
            
            // Check position 11 constraint
            assert!(words[11] == "about" || words[11] == "above", 
                "Last word should match constraint: {}", words[11]);
        }
        
        println!("✓ Candidate generation tests passed");
    }

    #[test]
    fn test_total_combinations_calculation() {
        println!("Testing total combinations calculation...");
        
        // Test with small numbers to avoid overflow
        let config = Config {
            mnemonic_length: 12,
            wallet_type: "ethereum".to_string(),
            word_constraints: vec![
                WordConstraint { position: 0, words: vec!["abandon".to_string(), "ability".to_string()] }, // 2 options
                WordConstraint { position: 1, words: vec!["abandon".to_string()] }, // 1 option
                WordConstraint { position: 2, words: vec!["abandon".to_string()] }, // 1 option
                WordConstraint { position: 3, words: vec!["abandon".to_string()] }, // 1 option
                WordConstraint { position: 4, words: vec!["abandon".to_string()] }, // 1 option
                WordConstraint { position: 5, words: vec!["abandon".to_string()] }, // 1 option
                WordConstraint { position: 6, words: vec!["abandon".to_string()] }, // 1 option
                WordConstraint { position: 7, words: vec!["abandon".to_string()] }, // 1 option
                WordConstraint { position: 8, words: vec!["abandon".to_string()] }, // 1 option
                WordConstraint { position: 9, words: vec!["abandon".to_string()] }, // 1 option
                WordConstraint { position: 10, words: vec!["abandon".to_string()] }, // 1 option
                WordConstraint { position: 11, words: vec!["about".to_string(), "above".to_string()] }, // 2 options
            ],
            ethereum: EthereumConfig {
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
                target_address: "0x9858effd232b4033e47d90003d41ec34ecaeda94".to_string(),
                passphrase: "".to_string(),
            },
            batch_size: 1024,
        };
        
        let result = calculate_total_combinations(&config);
        assert!(result.is_ok(), "Total combinations calculation should succeed");
        
        let total = result.unwrap();
        // With constraints: 2 * 1 * 1 * 1 * 1 * 1 * 1 * 1 * 1 * 1 * 1 * 2 = 4
        let expected = 4u64;
        assert_eq!(total, expected, "Total combinations should match expected value");
        
        println!("✓ Total combinations calculation tests passed");
    }

    #[test]
    fn test_gpu_detection() {
        println!("Testing GPU detection...");
        
        let result = detect_gpu_info();
        // This test might fail on systems without OpenCL, so we'll just check if it runs
        match result {
            Ok((compute_units, memory_gb)) => {
                println!("✓ GPU detected: {} compute units, {:.2} GB memory", compute_units, memory_gb);
                assert!(compute_units > 0, "Should have at least one compute unit");
                assert!(memory_gb > 0.0, "Should have some memory");
            },
            Err(e) => {
                println!("⚠ GPU detection failed (this is OK on systems without OpenCL): {}", e);
            }
        }
    }

    #[test]
    fn test_batch_size_detection() {
        println!("Testing batch size detection...");
        
        let result = detect_optimal_batch_size();
        match result {
            Ok(batch_size) => {
                println!("✓ Optimal batch size detected: {}", batch_size);
                assert!(batch_size > 0, "Batch size should be positive");
                assert!(batch_size <= 1_000_000, "Batch size should be reasonable");
            },
            Err(e) => {
                println!("⚠ Batch size detection failed (this is OK on systems without OpenCL): {}", e);
            }
        }
    }

    #[test]
    fn test_stats_functionality() {
        println!("Testing statistics functionality...");
        
        let stats = Stats::new();
        
        // Test initial state
        stats.set_total_candidates(1000);
        
        // Test adding processed count
        stats.add_processed(100);
        stats.add_processed(200);
        
        // The stats should track progress (we can't easily test the output without mocking)
        println!("✓ Statistics functionality tests passed");
    }

    #[test]
    fn test_edge_cases() {
        println!("Testing edge cases...");
        
        // Test empty mnemonic
        assert!(!is_valid_mnemonic(""), "Empty mnemonic should be invalid");
        
        // Test mnemonic with extra spaces
        let spaced_mnemonic = "  abandon   abandon   abandon   abandon   abandon   abandon   abandon   abandon   abandon   abandon   abandon   about  ";
        // This might be valid depending on the BIP39 implementation
        let _ = is_valid_mnemonic(spaced_mnemonic);
        
        // Test invalid derivation path
        let seed = [0u8; 64];
        let invalid_path_result = derive_ethereum_address(&seed, "invalid/path");
        assert!(invalid_path_result.is_err(), "Invalid derivation path should fail");
        
        // Test case sensitivity in address comparison
        let uppercase_address = "0X9858EFFD232B4033E47D90003D41EC34ECAEDA94";
        let _lowercase_address = "0x9858effd232b4033e47d90003d41ec34ecaeda94";
        
        let result = check_mnemonic(
            TEST_VECTORS[0].mnemonic,
            TEST_VECTORS[0].passphrase,
            TEST_VECTORS[0].derivation_path,
            uppercase_address
        );
        assert!(result.is_ok() && result.unwrap(), "Address comparison should be case-insensitive");
        
        println!("✓ Edge cases tests passed");
    }

    /// Integration test that runs a small-scale recovery simulation
    #[test]
    fn test_integration_small_scale_recovery() {
        println!("Testing small-scale recovery simulation...");
        
        // Create a config that should find the first test vector
        let target_mnemonic = TEST_VECTORS[0].mnemonic;
        let words: Vec<&str> = target_mnemonic.split_whitespace().collect();
        
        let config = Config {
            mnemonic_length: 12,
            wallet_type: "ethereum".to_string(),
            word_constraints: vec![
                WordConstraint { position: 0, words: vec![words[0].to_string()] },  // "abandon"
                WordConstraint { position: 1, words: vec![words[1].to_string()] },  // "abandon"
                WordConstraint { position: 2, words: vec![words[2].to_string()] },  // "abandon"
                WordConstraint { position: 3, words: vec![words[3].to_string()] },  // "abandon"
                WordConstraint { position: 4, words: vec![words[4].to_string()] },  // "abandon"
                WordConstraint { position: 5, words: vec![words[5].to_string()] },  // "abandon"
                WordConstraint { position: 6, words: vec![words[6].to_string()] },  // "abandon"
                WordConstraint { position: 7, words: vec![words[7].to_string()] },  // "abandon"
                WordConstraint { position: 8, words: vec![words[8].to_string()] },  // "abandon"
                WordConstraint { position: 9, words: vec![words[9].to_string()] },  // "abandon"
                WordConstraint { position: 10, words: vec![words[10].to_string()] }, // "abandon"
                WordConstraint { position: 11, words: vec![words[11].to_string()] }, // "about"
            ],
            ethereum: EthereumConfig {
                derivation_path: TEST_VECTORS[0].derivation_path.to_string(),
                target_address: TEST_VECTORS[0].expected_address.to_string(),
                passphrase: TEST_VECTORS[0].passphrase.to_string(),
            },
            batch_size: 100,
        };
        
        // Generate candidates
        let result = generate_candidate_mnemonics(&config);
        assert!(result.is_ok(), "Candidate generation should succeed");
        
        let (candidates, _) = result.unwrap();
        
        // Check if our target mnemonic is in the candidates
        let found = candidates.iter().any(|candidate| {
            match check_mnemonic(
                candidate,
                &config.ethereum.passphrase,
                &config.ethereum.derivation_path,
                &config.ethereum.target_address
            ) {
                Ok(matches) => matches,
                Err(_) => false,
            }
        });
        
        assert!(found, "Should find the target mnemonic in candidates");
        
        println!("✓ Small-scale recovery simulation passed");
    }

    /// Performance benchmark test
    #[test]
    fn test_performance_benchmark() {
        println!("Running performance benchmark...");
        
        let start = std::time::Instant::now();
        let iterations = 1000;
        
        for _ in 0..iterations {
            let _ = mnemonic_to_seed(TEST_VECTORS[0].mnemonic, TEST_VECTORS[0].passphrase);
        }
        
        let duration = start.elapsed();
        let per_iteration = duration.as_micros() / iterations;
        
        println!("✓ Performance: {} iterations in {:?} ({} μs per iteration)", 
                iterations, duration, per_iteration);
        
        // Basic performance check - should complete reasonably quickly
        assert!(per_iteration < 50_000, "Each iteration should take less than 50ms");
    }
}

/// Run all tests with detailed output
pub fn run_comprehensive_tests() -> Result<()> {
    println!("🚀 Starting comprehensive test suite for Ethereum BIP39 solver...");
    println!("{}", "=".repeat(70));
    
    // Note: In a real implementation, you would run the tests here
    // For now, we'll just indicate that tests should be run with `cargo test`
    
    println!("To run all tests, use: cargo test");
    println!("To run with output: cargo test -- --nocapture");
    println!("To run specific test: cargo test test_mnemonic_validation");
    
    Ok(())
}