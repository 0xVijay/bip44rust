use bip39::{Mnemonic, Language};
use std::str::FromStr;

fn main() {
    let mnemonic_str = "inner barely tiny cup busy ramp stuff accuse timber exercise then decline";
    
    match Mnemonic::from_str(mnemonic_str) {
        Ok(mnemonic) => {
            let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
            let word_list = Language::English.word_list();
            
            println!("Mnemonic: {}", mnemonic_str);
            println!("Word indices:");
            
            let mut indices = Vec::new();
            for (i, word) in words.iter().enumerate() {
                if let Some(index) = word_list.iter().position(|&w| w == *word) {
                    indices.push(index);
                    println!("  {}: {} -> {}", i, word, index);
                } else {
                    println!("  {}: {} -> NOT FOUND", i, word);
                }
            }
            
            println!("\nIndices array: {:?}", indices);
        }
        Err(e) => {
            println!("Error parsing mnemonic: {}", e);
        }
    }
}