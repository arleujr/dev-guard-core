use std::collections::HashMap;
use thiserror::Error;

/// Defines specific errors for the entropy module, ensuring
/// the application handles failures safely without panicking.
#[derive(Error, Debug, PartialEq)]
pub enum EntropyError {
    #[error("Cannot calculate entropy for an empty string")]
    EmptyString,
}

/// Calculates the Shannon Entropy of a given string slice.
/// Returns a `f64` representing the randomness degree or an `EntropyError`.
pub fn calculate_shannon_entropy(data: &str) -> Result<f64, EntropyError> {
    if data.is_empty() {
        return Err(EntropyError::EmptyString);
    }

    let mut frequency_map: HashMap<char, usize> = HashMap::new();
    
    for ch in data.chars() {
        *frequency_map.entry(ch).or_insert(0) += 1;
    }

    let len = data.chars().count() as f64;
    let mut entropy = 0.0;

    for &count in frequency_map.values() {
        let probability = count as f64 / len;
        entropy -= probability * probability.log2();
    }

    Ok(entropy)
}

/// Evaluates if a string is a potential secret based on an entropy threshold.
/// Production API keys usually present an entropy score above 4.5.
pub fn is_highly_random(data: &str, threshold: f64) -> Result<bool, EntropyError> {
    let entropy = calculate_shannon_entropy(data)?;
    Ok(entropy >= threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string_returns_error() {
        let result = calculate_shannon_entropy("");
        assert_eq!(result, Err(EntropyError::EmptyString));
    }

    #[test]
    fn test_low_entropy_for_repeated_chars() {
        // A string with the same char has entropy 0.0
        let entropy = calculate_shannon_entropy("aaaaaaa").unwrap();
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_high_entropy_for_random_string() {
        // Simulating a high-entropy API token
        let token = "hK9fX2wPzL1mNq8vT5rJ4kC7bV0xY3zW";
        let is_secret = is_highly_random(token, 4.0).unwrap();
        assert!(is_secret);
    }

    #[test]
    fn test_high_entropy_complex_secret() {
        // Simulating a complex random key structure
        let secret = "aB9x!zQp2@LmWk7#vYn4$jTc"; 
        let entropy = calculate_shannon_entropy(secret).unwrap();
        // Expecting high entropy (above 4.0) due to high character diversity
        assert!(entropy > 4.0);
    }

    #[test]
    fn test_low_entropy_string() {
        // A common, highly repetitive block of characters in code
        let not_a_secret = "aaaaabbbbbccccc"; 
        let entropy = calculate_shannon_entropy(not_a_secret).unwrap();
        // Expecting low entropy due to predictable distribution
        assert!(entropy < 2.0);
    }
}
