use anyhow::Result;
use serde_json::{Map, Value};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn audit(event: &str, fields: Value) -> Result<()> {
    let path = crate::config::audit_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut object = Map::new();
    object.insert("unix".to_string(), Value::from(unix));
    object.insert("event".to_string(), Value::from(event));
    if let Value::Object(fields) = fields {
        for (k, v) in fields {
            object.insert(k, v);
        }
    } else {
        object.insert("fields".to_string(), fields);
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    serde_json::to_writer(&mut file, &Value::Object(object))?;
    file.write_all(b"\n")?;
    Ok(())
}
