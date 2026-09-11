//! Freeze a complete call request from stdin into a project recipe on stdout.
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("request exceeds 1 MiB".into());
    }
    let recipe = amiga_operations::sandbox_recipe::SandboxRecipe::from_request_json(
        &bytes,
        amiga_operations::OperationLimits::default(),
    )?;
    let mut output = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, &recipe)?;
    writeln!(output)?;
    Ok(())
}
