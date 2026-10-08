//! Session data fetcher: trait + HTTP implementation + mock for tests.
//!
//! `SessionFetcher` abstracts over "get rows from a session" so the scorer
//! never depends on a live daemon.  Tests inject `MockFetcher`; production
//! code uses `HttpFetcher`.
//!
//! The HTTP implementation is best-effort: a connection refused or a 501 from
//! the daemon returns an empty Vec rather than an Err so the scorer still
//! produces a (zero-recall) report.

use serde_json::Value;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Retrieve session rows for compare scoring.
///
/// Each method returns a `Vec<Value>` — one JSON object per row.  Unknown
/// keys are ignored by the scorer; missing keys become NA counts.
pub trait SessionFetcher {
    fn fetch_files(&self) -> Result<Vec<Value>, String>;
    fn fetch_processes(&self) -> Result<Vec<Value>, String>;
    fn fetch_flows(&self) -> Result<Vec<Value>, String>;
}

// ---------------------------------------------------------------------------
// HTTP implementation (real daemon)
// ---------------------------------------------------------------------------

/// Fetch session rows from a running `agentwatchd` via its HTTP API.
pub struct HttpFetcher {
    base_url: String,
    token: Option<String>,
    session: String,
}

impl HttpFetcher {
    pub fn new(base_url: String, token: Option<String>, session: String) -> Self {
        Self {
            base_url,
            token,
            session,
        }
    }

    fn get_json(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}/api/v1{}", self.base_url.trim_end_matches('/'), path);
        let mut builder = ureq::get(&url);
        if let Some(tok) = &self.token {
            builder = builder.header("Authorization", &format!("Bearer {tok}"));
        }
        match builder.call() {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                if status == 501 || status == 404 {
                    // Feature not implemented or session not found — empty result.
                    return Ok(Value::Null);
                }
                if !(200..300).contains(&(status as usize)) {
                    return Err(format!("HTTP {status} for {url}"));
                }
                let text = resp
                    .body_mut()
                    .read_to_string()
                    .map_err(|e| format!("read body: {e}"))?;
                serde_json::from_str(&text).map_err(|e| format!("parse json: {e}"))
            }
            Err(err) => {
                // Connection refused, no daemon running — not fatal for compare.
                eprintln!("sim compare: cannot reach daemon ({err}); session data will be empty");
                Ok(Value::Null)
            }
        }
    }

    fn extract_array(v: &Value, key: &str) -> Vec<Value> {
        v.get(key)
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
    }
}

impl SessionFetcher for HttpFetcher {
    fn fetch_files(&self) -> Result<Vec<Value>, String> {
        let path = format!("/sessions/{}/files", self.session);
        let v = self.get_json(&path)?;
        Ok(Self::extract_array(&v, "files"))
    }

    fn fetch_processes(&self) -> Result<Vec<Value>, String> {
        let path = format!("/sessions/{}/processes", self.session);
        let v = self.get_json(&path)?;
        // The processes endpoint returns { "processes": [...] } or a flat array
        // depending on whether tree=1 was set.  Accept both.
        if let Some(arr) = v.as_array() {
            return Ok(arr.clone());
        }
        Ok(Self::extract_array(&v, "processes"))
    }

    fn fetch_flows(&self) -> Result<Vec<Value>, String> {
        let path = format!("/sessions/{}/flows", self.session);
        let v = self.get_json(&path)?;
        Ok(Self::extract_array(&v, "flows"))
    }
}

// ---------------------------------------------------------------------------
// Mock for unit tests
// ---------------------------------------------------------------------------

/// Inject pre-built rows without touching any network.
#[cfg(test)]
pub struct MockFetcher {
    pub files: Vec<Value>,
    pub processes: Vec<Value>,
    pub flows: Vec<Value>,
}

#[cfg(test)]
impl SessionFetcher for MockFetcher {
    fn fetch_files(&self) -> Result<Vec<Value>, String> {
        Ok(self.files.clone())
    }
    fn fetch_processes(&self) -> Result<Vec<Value>, String> {
        Ok(self.processes.clone())
    }
    fn fetch_flows(&self) -> Result<Vec<Value>, String> {
        Ok(self.flows.clone())
    }
}

// Unit tests live in compare/mod.rs which imports MockFetcher.
