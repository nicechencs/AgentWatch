//! Platform thresholds from `sim/thresholds/p1.toml`.
//!
//! E1 platforms assert recall and byte error. `tier = "S"` reports only.
//! `macos.m1` is the wider byte budget (REQ-04: sample collection < 15%).

use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq)]
pub struct Thresholds {
    platforms: Vec<PlatformThreshold>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlatformThreshold {
    pub name: String,
    /// `E1` asserts. `S` reports and does not fail the run.
    pub tier: Tier,
    /// Inclusive lower bound, as a fraction (0.95 = 95%).
    pub recall_min: f64,
    /// Exclusive upper bound, as a fraction (0.05 = 5%).
    pub byte_error_max: f64,
    /// When set, byte error uses this bound instead (macOS M1).
    pub m1_byte_error_max: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    E1,
    S,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActiveThreshold {
    pub platform: String,
    pub tier: Tier,
    pub recall_min: f64,
    pub byte_error_max: f64,
    /// `true` when the M1 byte budget replaced the E1 one.
    pub m1: bool,
}

#[derive(Debug, Deserialize)]
struct File {
    #[serde(default)]
    platform: Vec<PlatformRow>,
}

#[derive(Debug, Deserialize)]
struct PlatformRow {
    name: String,
    #[serde(default)]
    tier: String,
    recall_min: f64,
    byte_error_max: f64,
    #[serde(default)]
    m1_byte_error_max: Option<f64>,
}

impl Thresholds {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path)
            .map_err(|err| format!("read {}: {err}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let file: File = toml::from_str(text).map_err(|err| format!("parse thresholds: {err}"))?;
        if file.platform.is_empty() {
            return Err("thresholds file has no [[platform]] table".to_string());
        }
        let mut platforms = Vec::new();
        for row in file.platform {
            let tier = match row.tier.as_str() {
                "E1" | "e1" => Tier::E1,
                "S" | "s" => Tier::S,
                other => return Err(format!("unknown tier `{other}` for {}", row.name)),
            };
            if !(0.0..=1.0).contains(&row.recall_min) {
                return Err(format!("recall_min out of range for {}", row.name));
            }
            if !(0.0..=1.0).contains(&row.byte_error_max) {
                return Err(format!("byte_error_max out of range for {}", row.name));
            }
            platforms.push(PlatformThreshold {
                name: row.name,
                tier,
                recall_min: row.recall_min,
                byte_error_max: row.byte_error_max,
                m1_byte_error_max: row.m1_byte_error_max,
            });
        }
        Ok(Self { platforms })
    }

    /// `macos-m1` selects the macOS row and the M1 byte budget.
    pub fn select(&self, platform: &str) -> Result<ActiveThreshold, String> {
        let m1 = platform.eq_ignore_ascii_case("macos-m1");
        let key = if m1 { "macos" } else { platform };
        let row = self
            .platforms
            .iter()
            .find(|row| row.name.eq_ignore_ascii_case(key))
            .ok_or_else(|| format!("no threshold for platform `{platform}`"))?;
        let byte_error_max = if m1 {
            row.m1_byte_error_max
                .ok_or_else(|| "macos threshold has no m1_byte_error_max".to_string())?
        } else {
            row.byte_error_max
        };
        Ok(ActiveThreshold {
            platform: platform.to_string(),
            tier: row.tier,
            recall_min: row.recall_min,
            byte_error_max,
            m1,
        })
    }
}
