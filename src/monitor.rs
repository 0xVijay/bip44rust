//! Progress monitoring and performance tracking

use crate::error::Result;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use std::sync::{Arc, Mutex, atomic::{AtomicU64, AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use std::thread;
use tracing::{info, debug};

/// Performance metrics for the recovery process
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// Total candidates processed
    pub candidates_processed: u64,
    /// Candidates processed per second
    pub candidates_per_second: f64,
    /// Total time elapsed
    pub elapsed_time: Duration,
    /// Estimated time remaining
    pub estimated_remaining: Option<Duration>,
    /// Memory usage in MB
    pub memory_usage_mb: f64,
    /// GPU utilization percentage (if applicable)
    pub gpu_utilization: Option<f64>,
    /// Success rate (matches found / candidates processed)
    pub success_rate: f64,
    /// Number of matches found
    pub matches_found: u64,
}

/// Progress tracking state
#[derive(Debug)]
pub struct ProgressState {
    /// Total search space size
    pub total_candidates: u64,
    /// Candidates processed so far
    pub processed: AtomicU64,
    /// Number of matches found
    pub matches: AtomicU64,
    /// Start time
    pub start_time: Mutex<Instant>,
    /// Whether the process is running
    pub is_running: AtomicBool,
    /// Whether a match was found
    pub match_found: AtomicBool,
}

/// Monitor for tracking recovery progress
#[derive(Debug)]
pub struct RecoveryMonitor {
    /// Progress state
    state: Arc<ProgressState>,
    /// Progress bar for visual feedback
    progress_bar: Option<ProgressBar>,
    /// Multi-progress for multiple bars
    _multi_progress: Option<MultiProgress>,
    /// Update interval for progress reporting
    _update_interval: Duration,
    /// Performance history for rate calculation
    performance_history: Arc<Mutex<Vec<(Instant, u64)>>>,
}

/// Configuration for the monitor
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Whether to show progress bar
    pub show_progress_bar: bool,
    /// Update interval in milliseconds
    pub update_interval_ms: u64,
    /// Maximum history entries for rate calculation
    pub max_history_entries: usize,
    /// Whether to log performance metrics
    pub log_metrics: bool,
    /// Log interval in seconds
    pub log_interval_seconds: u64,
}

/// Checkpoint data for resuming operations
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    /// Number of candidates processed
    pub processed: u64,
    /// Total candidates in search space
    pub total: u64,
    /// Timestamp of checkpoint
    pub timestamp: std::time::SystemTime,
    /// Current batch position or state
    pub batch_position: u64,
    /// Any additional state data
    pub state_data: std::collections::HashMap<String, String>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            show_progress_bar: true,
            update_interval_ms: 1000,
            max_history_entries: 60,
            log_metrics: true,
            log_interval_seconds: 10,
        }
    }
}

impl RecoveryMonitor {
    /// Create a new recovery monitor
    pub fn new(total_candidates: u64, config: MonitorConfig) -> Self {
        let state = Arc::new(ProgressState {
            total_candidates,
            processed: AtomicU64::new(0),
            matches: AtomicU64::new(0),
            start_time: Mutex::new(Instant::now()),
            is_running: AtomicBool::new(false),
            match_found: AtomicBool::new(false),
        });
        
        let (progress_bar, multi_progress) = if config.show_progress_bar {
            let multi = MultiProgress::new();
            let pb = multi.add(ProgressBar::new(total_candidates));
            
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
                    .unwrap()
                    .progress_chars("#>-")
            );
            
            pb.set_message("Searching for seed phrase...");
            (Some(pb), Some(multi))
        } else {
            (None, None)
        };
        
        Self {
            state,
            progress_bar,
            _multi_progress: multi_progress,
            _update_interval: Duration::from_millis(config.update_interval_ms),
            performance_history: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    /// Start monitoring
    pub fn start(&self) {
        self.state.is_running.store(true, Ordering::SeqCst);
        if let Ok(mut start_time) = self.state.start_time.lock() {
            *start_time = Instant::now();
        }
        
        if let Some(pb) = &self.progress_bar {
            pb.reset();
        }
        
        info!("Recovery monitoring started");
    }
    
    /// Stop monitoring
    pub fn stop(&self) {
        self.state.is_running.store(false, Ordering::SeqCst);
        
        if let Some(pb) = &self.progress_bar {
            pb.finish_with_message("Recovery completed");
        }
        
        info!("Recovery monitoring stopped");
    }
    
    /// Update progress with number of candidates processed
    pub fn update_progress(&self, candidates_processed: u64) {
        let old_value = self.state.processed.fetch_add(candidates_processed, Ordering::SeqCst);
        let new_value = old_value + candidates_processed;
        
        // Update progress bar
        if let Some(pb) = &self.progress_bar {
            pb.set_position(new_value);
            
            // Update message with current rate
            if let Ok(metrics) = self.get_metrics() {
                let msg = format!(
                    "{:.0} candidates/sec, {} matches",
                    metrics.candidates_per_second,
                    metrics.matches_found
                );
                pb.set_message(msg);
            }
        }
        
        // Update performance history
        if let Ok(mut history) = self.performance_history.lock() {
            let now = Instant::now();
            history.push((now, new_value));
            
            // Keep only recent entries
            let cutoff = now - Duration::from_secs(60);
            history.retain(|(time, _)| *time > cutoff);
        }
        
        debug!("Progress updated: {} candidates processed", new_value);
    }
    
    /// Record a match found
    pub fn record_match(&self) {
        self.state.matches.fetch_add(1, Ordering::SeqCst);
        self.state.match_found.store(true, Ordering::SeqCst);
        
        if let Some(pb) = &self.progress_bar {
            pb.println("🎉 Match found!");
        }
        
        info!("Match found! Total matches: {}", self.get_match_count());
    }
    
    /// Get current performance metrics
    pub fn get_metrics(&self) -> Result<PerformanceMetrics> {
        let processed = self.state.processed.load(Ordering::SeqCst);
        let matches = self.state.matches.load(Ordering::SeqCst);
        let elapsed = if let Ok(start_time) = self.state.start_time.lock() {
            start_time.elapsed()
        } else {
            Duration::from_secs(0)
        };
        
        let candidates_per_second = if elapsed.as_secs_f64() > 0.0 {
            processed as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        
        let estimated_remaining = if candidates_per_second > 0.0 {
            let remaining = self.state.total_candidates.saturating_sub(processed);
            let seconds_remaining = remaining as f64 / candidates_per_second;
            Some(Duration::from_secs_f64(seconds_remaining))
        } else {
            None
        };
        
        let success_rate = if processed > 0 {
            matches as f64 / processed as f64
        } else {
            0.0
        };
        
        // Get memory usage (simplified)
        let memory_usage_mb = self.get_memory_usage_mb();
        
        Ok(PerformanceMetrics {
            candidates_processed: processed,
            candidates_per_second,
            elapsed_time: elapsed,
            estimated_remaining,
            memory_usage_mb,
            gpu_utilization: None, // TODO: Implement GPU monitoring
            success_rate,
            matches_found: matches,
        })
    }
    
    /// Get current processing rate (candidates per second)
    pub fn get_current_rate(&self) -> f64 {
        if let Ok(history) = self.performance_history.lock() {
            if history.len() < 2 {
                return 0.0;
            }
            
            let recent_entries: Vec<_> = history.iter().rev().take(10).collect();
            if recent_entries.len() < 2 {
                return 0.0;
            }
            
            let (latest_time, latest_count) = recent_entries[0];
            let (earliest_time, earliest_count) = recent_entries[recent_entries.len() - 1];
            
            let time_diff = latest_time.duration_since(*earliest_time).as_secs_f64();
            let count_diff = latest_count.saturating_sub(*earliest_count);
            
            if time_diff > 0.0 {
                count_diff as f64 / time_diff
            } else {
                0.0
            }
        } else {
            0.0
        }
    }
    
    /// Get total candidates processed
    pub fn get_processed_count(&self) -> u64 {
        self.state.processed.load(Ordering::SeqCst)
    }
    
    /// Get total matches found
    pub fn get_match_count(&self) -> u64 {
        self.state.matches.load(Ordering::SeqCst)
    }
    
    /// Check if monitoring is running
    pub fn is_running(&self) -> bool {
        self.state.is_running.load(Ordering::SeqCst)
    }
    
    /// Check if a match was found
    pub fn has_match(&self) -> bool {
        self.state.match_found.load(Ordering::SeqCst)
    }
    
    /// Get completion percentage
    pub fn get_completion_percentage(&self) -> f64 {
        let processed = self.state.processed.load(Ordering::SeqCst);
        if self.state.total_candidates == 0 {
            return 0.0;
        }
        (processed as f64 / self.state.total_candidates as f64) * 100.0
    }
    
    /// Create a checkpoint for resuming
    pub fn create_checkpoint(&self, batch_position: u64) -> Checkpoint {
        Checkpoint {
            processed: self.get_processed_count(),
            total: self.state.total_candidates,
            timestamp: std::time::SystemTime::now(),
            batch_position,
            state_data: std::collections::HashMap::new(),
        }
    }
    
    /// Restore from checkpoint
    pub fn restore_from_checkpoint(&self, checkpoint: &Checkpoint) {
        self.state.processed.store(checkpoint.processed, Ordering::SeqCst);
        
        if let Some(pb) = &self.progress_bar {
            pb.set_position(checkpoint.processed);
        }
        
        info!("Restored from checkpoint: {} candidates processed", checkpoint.processed);
    }
    
    /// Start a background monitoring thread
    pub fn start_background_monitoring(&self, config: MonitorConfig) -> thread::JoinHandle<()> {
        let state = Arc::clone(&self.state);
        let _performance_history = Arc::clone(&self.performance_history);
        
        thread::spawn(move || {
            let mut last_log = Instant::now();
            let log_interval = Duration::from_secs(config.log_interval_seconds);
            
            while state.is_running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(config.update_interval_ms));
                
                if config.log_metrics && last_log.elapsed() >= log_interval {
                    let processed = state.processed.load(Ordering::SeqCst);
                    let matches = state.matches.load(Ordering::SeqCst);
                    let elapsed = if let Ok(start_time) = state.start_time.lock() {
                        start_time.elapsed()
                    } else {
                        Duration::from_secs(0)
                    };
                    
                    let rate = if elapsed.as_secs_f64() > 0.0 {
                        processed as f64 / elapsed.as_secs_f64()
                    } else {
                        0.0
                    };
                    
                    info!(
                        "Progress: {}/{} ({:.1}%), Rate: {:.0} c/s, Matches: {}, Elapsed: {:?}",
                        processed,
                        state.total_candidates,
                        (processed as f64 / state.total_candidates as f64) * 100.0,
                        rate,
                        matches,
                        elapsed
                    );
                    
                    last_log = Instant::now();
                }
            }
        })
    }
    
    /// Get estimated memory usage in MB (simplified implementation)
    fn get_memory_usage_mb(&self) -> f64 {
        // This is a simplified implementation
        // In a real implementation, you would use system APIs to get actual memory usage
        let processed = self.state.processed.load(Ordering::SeqCst);
        
        // Rough estimate: each candidate uses about 1KB of memory during processing
        let estimated_mb = (processed as f64 * 1024.0) / (1024.0 * 1024.0);
        estimated_mb.max(10.0) // Minimum 10MB baseline
    }
}

/// Utility functions for monitoring
pub mod utils {
    use super::*;
    
    /// Format duration in human-readable format
    pub fn format_duration(duration: Duration) -> String {
        let total_seconds = duration.as_secs();
        let hours = total_seconds / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;
        
        if hours > 0 {
            format!("{}h {}m {}s", hours, minutes, seconds)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, seconds)
        } else {
            format!("{}s", seconds)
        }
    }
    
    /// Format large numbers with commas
    pub fn format_number(num: u64) -> String {
        let num_str = num.to_string();
        let mut result = String::new();
        
        for (i, c) in num_str.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                result.push(',');
            }
            result.push(c);
        }
        
        result.chars().rev().collect()
    }
    
    /// Format rate with appropriate units
    pub fn format_rate(rate: f64) -> String {
        if rate >= 1_000_000.0 {
            format!("{:.1}M/s", rate / 1_000_000.0)
        } else if rate >= 1_000.0 {
            format!("{:.1}K/s", rate / 1_000.0)
        } else {
            format!("{:.0}/s", rate)
        }
    }
    
    /// Calculate search space size from word constraints
    pub fn calculate_search_space(word_constraints: &[(usize, Vec<String>)]) -> u64 {
        word_constraints
            .iter()
            .map(|(_, words)| words.len() as u64)
            .product()
    }
    
    /// Estimate completion time
    pub fn estimate_completion_time(processed: u64, total: u64, rate: f64) -> Option<Duration> {
        if rate <= 0.0 || processed >= total {
            return None;
        }
        
        let remaining = total - processed;
        let seconds = remaining as f64 / rate;
        Some(Duration::from_secs_f64(seconds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    
    #[test]
    fn test_monitor_creation() {
        let config = MonitorConfig::default();
        let monitor = RecoveryMonitor::new(1000, config);
        
        assert_eq!(monitor.get_processed_count(), 0);
        assert_eq!(monitor.get_match_count(), 0);
        assert!(!monitor.is_running());
        assert!(!monitor.has_match());
    }
    
    #[test]
    fn test_progress_tracking() {
        let config = MonitorConfig {
            show_progress_bar: false,
            ..MonitorConfig::default()
        };
        let monitor = RecoveryMonitor::new(1000, config);
        
        monitor.start();
        assert!(monitor.is_running());
        
        monitor.update_progress(100);
        assert_eq!(monitor.get_processed_count(), 100);
        assert_eq!(monitor.get_completion_percentage(), 10.0);
        
        monitor.update_progress(200);
        assert_eq!(monitor.get_processed_count(), 300);
        assert_eq!(monitor.get_completion_percentage(), 30.0);
        
        monitor.stop();
        assert!(!monitor.is_running());
    }
    
    #[test]
    fn test_match_recording() {
        let config = MonitorConfig {
            show_progress_bar: false,
            ..MonitorConfig::default()
        };
        let monitor = RecoveryMonitor::new(1000, config);
        
        assert_eq!(monitor.get_match_count(), 0);
        assert!(!monitor.has_match());
        
        monitor.record_match();
        assert_eq!(monitor.get_match_count(), 1);
        assert!(monitor.has_match());
        
        monitor.record_match();
        assert_eq!(monitor.get_match_count(), 2);
    }
    
    #[test]
    fn test_metrics() {
        let config = MonitorConfig {
            show_progress_bar: false,
            ..MonitorConfig::default()
        };
        let monitor = RecoveryMonitor::new(1000, config);
        
        monitor.start();
        
        // Wait a bit to ensure elapsed time > 0
        thread::sleep(Duration::from_millis(10));
        
        monitor.update_progress(100);
        
        let metrics = monitor.get_metrics().unwrap();
        assert_eq!(metrics.candidates_processed, 100);
        assert!(metrics.candidates_per_second > 0.0);
        assert!(metrics.elapsed_time.as_millis() > 0);
        assert_eq!(metrics.matches_found, 0);
    }
    
    #[test]
    fn test_checkpoint() {
        let config = MonitorConfig {
            show_progress_bar: false,
            ..MonitorConfig::default()
        };
        let monitor = RecoveryMonitor::new(1000, config);
        
        monitor.update_progress(500);
        let checkpoint = monitor.create_checkpoint(250);
        
        assert_eq!(checkpoint.processed, 500);
        assert_eq!(checkpoint.total, 1000);
        assert_eq!(checkpoint.batch_position, 250);
        
        // Create new monitor and restore
        let monitor2 = RecoveryMonitor::new(1000, MonitorConfig {
            show_progress_bar: false,
            ..MonitorConfig::default()
        });
        
        monitor2.restore_from_checkpoint(&checkpoint);
        assert_eq!(monitor2.get_processed_count(), 500);
    }
    
    #[test]
    fn test_utils() {
        assert_eq!(utils::format_duration(Duration::from_secs(3661)), "1h 1m 1s");
        assert_eq!(utils::format_duration(Duration::from_secs(61)), "1m 1s");
        assert_eq!(utils::format_duration(Duration::from_secs(1)), "1s");
        
        assert_eq!(utils::format_number(1234567), "1,234,567");
        assert_eq!(utils::format_number(123), "123");
        
        assert_eq!(utils::format_rate(1500000.0), "1.5M/s");
        assert_eq!(utils::format_rate(1500.0), "1.5K/s");
        assert_eq!(utils::format_rate(150.0), "150/s");
    }
}