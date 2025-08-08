//! Candidate phrase generation from word constraints

use crate::config::RecoveryConfig;
use crate::error::{GeneratorError, Result};
use std::collections::HashMap;
use rayon::prelude::*;

/// A candidate mnemonic phrase
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The words in the mnemonic phrase
    pub words: Vec<String>,
    /// The phrase as a space-separated string
    pub phrase: String,
    /// Unique identifier for this candidate
    pub id: u64,
}

/// Generator for creating candidate phrases from word constraints
#[derive(Debug)]
pub struct CandidateGenerator {
    /// Word constraints mapped by position
    constraints: HashMap<usize, Vec<String>>,
    /// Length of the mnemonic
    mnemonic_length: usize,
    /// Current state for iteration
    current_indices: Vec<usize>,
    /// Total number of combinations
    total_combinations: u64,
    /// Current combination index
    current_combination: u64,
    /// Whether the generator is exhausted
    exhausted: bool,
}

/// Batch of candidates for processing
#[derive(Debug, Clone)]
pub struct CandidateBatch {
    /// The candidates in this batch
    pub candidates: Vec<Candidate>,
    /// Batch identifier
    pub batch_id: u64,
    /// Starting combination index for this batch
    pub start_index: u64,
    /// Ending combination index for this batch
    pub end_index: u64,
}

/// Iterator for generating candidate batches
pub struct BatchIterator {
    generator: CandidateGenerator,
    batch_size: usize,
    batch_counter: u64,
}

impl Candidate {
    /// Create a new candidate from words
    pub fn new(words: Vec<String>, id: u64) -> Self {
        let phrase = words.join(" ");
        Self { words, phrase, id }
    }
    
    /// Get the phrase as a string slice
    pub fn as_str(&self) -> &str {
        &self.phrase
    }
    
    /// Get the number of words
    pub fn word_count(&self) -> usize {
        self.words.len()
    }
    
    /// Validate that this candidate is a valid BIP39 mnemonic
    pub fn validate_bip39(&self) -> Result<()> {
        use bip39::Mnemonic;
        
        Mnemonic::parse(&self.phrase)
            .map_err(|_e| GeneratorError::InvalidWordCombination(
                vec![0] // TODO: Better error reporting
            ))?;
        
        Ok(())
    }
}

impl CandidateGenerator {
    /// Create a new generator from configuration
    pub fn new(config: &RecoveryConfig) -> Result<Self> {
        let constraints = config.get_constraints_map()
            .into_iter()
            .map(|(pos, words)| (pos, words.clone()))
            .collect();
        
        let total_combinations = config.calculate_search_space();
        
        // Check if search space is reasonable
        const MAX_SEARCH_SPACE: u64 = 1_000_000_000_000; // 1 trillion
        if total_combinations > MAX_SEARCH_SPACE {
            return Err(GeneratorError::SearchSpaceTooLarge(total_combinations).into());
        }
        
        let current_indices = vec![0; config.mnemonic_length];
        
        Ok(Self {
            constraints,
            mnemonic_length: config.mnemonic_length,
            current_indices,
            total_combinations,
            current_combination: 0,
            exhausted: false,
        })
    }
    
    /// Get the total number of combinations
    pub fn total_combinations(&self) -> u64 {
        self.total_combinations
    }
    
    /// Get the current combination index
    pub fn current_index(&self) -> u64 {
        self.current_combination
    }
    
    /// Check if the generator is exhausted
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }
    
    /// Generate the next candidate
    pub fn next_candidate(&mut self) -> Result<Option<Candidate>> {
        if self.exhausted {
            return Ok(None);
        }
        
        // Generate current candidate
        let candidate = self.generate_current_candidate()?;
        
        // Advance to next combination
        self.advance_indices();
        
        Ok(Some(candidate))
    }
    
    /// Generate a specific candidate by combination index
    pub fn generate_candidate_at_index(&self, index: u64) -> Result<Candidate> {
        if index >= self.total_combinations {
            return Err(GeneratorError::InvalidWordCombination(vec![]).into());
        }
        
        let indices = self.index_to_indices(index);
        self.generate_candidate_from_indices(&indices, index)
    }
    
    /// Generate a batch of candidates
    pub fn generate_batch(&mut self, batch_size: usize) -> Result<Option<CandidateBatch>> {
        if self.exhausted {
            return Ok(None);
        }
        
        let start_index = self.current_combination;
        let mut candidates = Vec::with_capacity(batch_size);
        
        for _ in 0..batch_size {
            if let Some(candidate) = self.next_candidate()? {
                candidates.push(candidate);
            } else {
                break;
            }
        }
        
        if candidates.is_empty() {
            return Ok(None);
        }
        
        let end_index = self.current_combination - 1;
        let batch_id = start_index / batch_size as u64;
        
        Ok(Some(CandidateBatch {
            candidates,
            batch_id,
            start_index,
            end_index,
        }))
    }
    
    /// Generate candidates in parallel for a range
    pub fn generate_range_parallel(&self, start: u64, end: u64) -> Result<Vec<Candidate>> {
        if start >= end || end > self.total_combinations {
            return Err(GeneratorError::InvalidWordCombination(vec![]).into());
        }
        
        let candidates: Result<Vec<_>> = (start..end)
            .into_par_iter()
            .map(|index| self.generate_candidate_at_index(index))
            .collect();
        
        candidates
    }
    
    /// Create a batch iterator
    pub fn batch_iterator(self, batch_size: usize) -> BatchIterator {
        BatchIterator {
            generator: self,
            batch_size,
            batch_counter: 0,
        }
    }
    
    /// Reset the generator to the beginning
    pub fn reset(&mut self) {
        self.current_indices.fill(0);
        self.current_combination = 0;
        self.exhausted = false;
    }
    
    /// Skip to a specific combination index
    pub fn skip_to(&mut self, index: u64) -> Result<()> {
        if index >= self.total_combinations {
            self.exhausted = true;
            return Ok(());
        }
        
        self.current_indices = self.index_to_indices(index);
        self.current_combination = index;
        self.exhausted = false;
        
        Ok(())
    }
    
    /// Generate current candidate from current indices
    fn generate_current_candidate(&self) -> Result<Candidate> {
        self.generate_candidate_from_indices(&self.current_indices, self.current_combination)
    }
    
    /// Generate candidate from specific indices
    fn generate_candidate_from_indices(&self, indices: &[usize], id: u64) -> Result<Candidate> {
        let mut words = Vec::with_capacity(self.mnemonic_length);
        
        for (position, &word_index) in indices.iter().enumerate() {
            let position_words = self.constraints.get(&position)
                .ok_or_else(|| GeneratorError::InvalidWordCombination(vec![position]))?;
            
            if word_index >= position_words.len() {
                return Err(GeneratorError::InvalidWordCombination(vec![position]).into());
            }
            
            words.push(position_words[word_index].clone());
        }
        
        Ok(Candidate::new(words, id))
    }
    
    /// Advance indices to next combination
    fn advance_indices(&mut self) {
        self.current_combination += 1;
        
        if self.current_combination >= self.total_combinations {
            self.exhausted = true;
            return;
        }
        
        // Increment indices like an odometer
        for position in 0..self.mnemonic_length {
            let position_words = &self.constraints[&position];
            self.current_indices[position] += 1;
            
            if self.current_indices[position] < position_words.len() {
                break; // No carry needed
            }
            
            // Carry to next position
            self.current_indices[position] = 0;
        }
    }
    
    /// Convert linear index to multi-dimensional indices
    fn index_to_indices(&self, mut index: u64) -> Vec<usize> {
        let mut indices = vec![0; self.mnemonic_length];
        
        for position in 0..self.mnemonic_length {
            let position_words = &self.constraints[&position];
            let word_count = position_words.len() as u64;
            
            indices[position] = (index % word_count) as usize;
            index /= word_count;
        }
        
        indices
    }
}

impl Iterator for BatchIterator {
    type Item = Result<CandidateBatch>;
    
    fn next(&mut self) -> Option<Self::Item> {
        match self.generator.generate_batch(self.batch_size) {
            Ok(Some(mut batch)) => {
                batch.batch_id = self.batch_counter;
                self.batch_counter += 1;
                Some(Ok(batch))
            }
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl CandidateBatch {
    /// Get the number of candidates in this batch
    pub fn len(&self) -> usize {
        self.candidates.len()
    }
    
    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }
    
    /// Get candidates as phrases
    pub fn phrases(&self) -> Vec<&str> {
        self.candidates.iter().map(|c| c.as_str()).collect()
    }
    
    /// Validate all candidates in the batch
    pub fn validate_all(&self) -> Result<()> {
        for candidate in &self.candidates {
            candidate.validate_bip39()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RecoveryConfig, WordConstraint, EthereumConfig};
    
    fn create_test_config() -> RecoveryConfig {
        RecoveryConfig {
            word_constraints: vec![
                WordConstraint {
                    position: 0,
                    words: vec!["abandon".to_string(), "ability".to_string()],
                },
                WordConstraint {
                    position: 1,
                    words: vec!["able".to_string(), "about".to_string(), "above".to_string()],
                },
            ],
            ethereum: EthereumConfig {
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
                target_address: "0x1234567890123456789012345678901234567890".to_string(),
                passphrase: String::new(),
            },
            mnemonic_length: 2,
            wallet_type: "ethereum".to_string(),
            batch_size: 1000,
            num_threads: 1,
            use_gpu: false,
            max_memory_mb: 1024,
        }
    }
    
    #[test]
    fn test_generator_creation() {
        let config = create_test_config();
        let generator = CandidateGenerator::new(&config).unwrap();
        
        assert_eq!(generator.total_combinations(), 6); // 2 * 3 = 6
        assert_eq!(generator.current_index(), 0);
        assert!(!generator.is_exhausted());
    }
    
    #[test]
    fn test_candidate_generation() {
        let config = create_test_config();
        let mut generator = CandidateGenerator::new(&config).unwrap();
        
        let candidate = generator.next_candidate().unwrap().unwrap();
        assert_eq!(candidate.words, vec!["abandon", "able"]);
        assert_eq!(candidate.phrase, "abandon able");
        assert_eq!(candidate.id, 0);
        
        let candidate = generator.next_candidate().unwrap().unwrap();
        assert_eq!(candidate.words, vec!["ability", "able"]);
        assert_eq!(candidate.id, 1);
    }
    
    #[test]
    fn test_batch_generation() {
        let config = create_test_config();
        let mut generator = CandidateGenerator::new(&config).unwrap();
        
        let batch = generator.generate_batch(3).unwrap().unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(batch.start_index, 0);
        assert_eq!(batch.end_index, 2);
        
        let phrases = batch.phrases();
        assert_eq!(phrases[0], "abandon able");
        assert_eq!(phrases[1], "ability able");
        assert_eq!(phrases[2], "abandon about");
    }
    
    #[test]
    fn test_parallel_generation() {
        let config = create_test_config();
        let generator = CandidateGenerator::new(&config).unwrap();
        
        let candidates = generator.generate_range_parallel(0, 3).unwrap();
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].phrase, "abandon able");
        assert_eq!(candidates[1].phrase, "ability able");
        assert_eq!(candidates[2].phrase, "abandon about");
    }
}