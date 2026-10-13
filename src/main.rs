use clap::{Args, Parser, Subcommand};
use rev_core::cli::*;
use rev_core::mcp::McpServer;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "rev-core",
    author = "Ronit Gupta <ronitgupta138@gmail.com>",
    version,
    about = "Autonomous reverse engineering engine and Model Context Protocol (MCP) server for binaries and applications.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Inspect binary headers, architecture, entrypoint, sections, and dependencies
    Inspect {
        /// Target binary file path (ELF, PE)
        file: PathBuf,
        /// Output findings as raw JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Check security mitigations (NX, PIE, RELRO, Stack Canaries, ASLR)
    Mitigations {
        /// Target binary file path
        file: PathBuf,
    },

    /// Disassemble machine code instructions (x86_64, arm64, riscv64) at an offset
    Disasm {
        /// Target binary file path
        file: PathBuf,
        /// Byte offset in file (decimal or 0x hex)
        #[arg(long, default_value = "0")]
        offset: String,
        /// Number of bytes to decode
        #[arg(long, default_value_t = 64)]
        length: usize,
        /// Maximum number of instructions to format
        #[arg(long, default_value_t = 20)]
        count: usize,
        /// Target architecture: x86_64, arm64, or riscv64
        #[arg(long, default_value = "x86_64")]
        arch: String,
    },

    /// Reconstruct Control Flow Graph (CFG) and basic blocks from code slice
    Cfg {
        /// Target binary file path
        file: PathBuf,
        /// Byte offset in file (decimal or 0x hex)
        #[arg(long, default_value = "0")]
        offset: String,
        /// Maximum number of instructions to process
        #[arg(long, default_value_t = 100)]
        max_instructions: usize,
        /// Diagram format: ascii or mermaid
        #[arg(long, default_value = "mermaid")]
        format: String,
    },

    /// Calculate Shannon entropy to detect packed, compressed or encrypted sections
    Entropy {
        /// Target file path
        file: PathBuf,
    },

    /// Scan binary for cryptographic state constants (AES, ChaCha20, SHA, MD5)
    Crypto {
        /// Target file path
        file: PathBuf,
    },

    /// Scan Electron application directory for IPC attack surfaces and security postures
    Electron {
        /// Directory containing extracted Electron app files
        dir: PathBuf,
    },

    /// Inspect WebAssembly (WASM) binary module, exports, imports, and sections
    Wasm {
        /// Target .wasm file path
        file: PathBuf,
    },

    /// Decompile a symbol using an external headless decompiler (rizin/radare2/ghidra)
    Decompile {
        /// Target binary file path
        file: PathBuf,
        /// Function symbol name or hex address
        symbol: String,
        /// Maximum timeout in seconds
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },

    /// List available external headless decompiler backends installed on this system
    Backends,

    /// Live process virtual memory forensics and dangerous RWX page detection
    Proc {
        /// Target Process ID (PID)
        pid: u32,
    },

    /// Electron ASAR archive inspection and extraction
    Asar(AsarArgs),

    /// Launch stdio Model Context Protocol (MCP) server for AI agents
    Mcp,
}

#[derive(Args, Debug)]
struct AsarArgs {
    #[command(subcommand)]
    command: AsarSubcommand,
}

#[derive(Subcommand, Debug)]
enum AsarSubcommand {
    /// List files and directories inside an ASAR archive
    List {
        /// Path to .asar file
        file: PathBuf,
    },
    /// Unpack all contents of an ASAR archive to a destination directory
    Unpack {
        /// Path to .asar file
        file: PathBuf,
        /// Output destination directory
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect { file, json } => {
            cmd_inspect(&file, json)?;
        }
        Commands::Mitigations { file } => {
            cmd_mitigations(&file)?;
        }
        Commands::Disasm {
            file,
            offset,
            length,
            count,
            arch,
        } => {
            let parsed_offset = if offset.starts_with("0x") || offset.starts_with("0X") {
                u64::from_str_radix(&offset[2..], 16)?
            } else {
                offset.parse::<u64>()?
            };
            cmd_disasm(&file, parsed_offset, length, count, &arch)?;
        }
        Commands::Cfg {
            file,
            offset,
            max_instructions,
            format,
        } => {
            let parsed_offset = if offset.starts_with("0x") || offset.starts_with("0X") {
                u64::from_str_radix(&offset[2..], 16)?
            } else {
                offset.parse::<u64>()?
            };
            cmd_cfg(&file, parsed_offset, max_instructions, &format)?;
        }
        Commands::Entropy { file } => {
            cmd_entropy(&file)?;
        }
        Commands::Crypto { file } => {
            cmd_crypto(&file)?;
        }
        Commands::Electron { dir } => {
            cmd_electron(&dir)?;
        }
        Commands::Wasm { file } => {
            cmd_wasm(&file)?;
        }
        Commands::Decompile { file, symbol, timeout } => {
            cmd_decompile(&file, &symbol, timeout)?;
        }
        Commands::Backends => {
            cmd_backends()?;
        }
        Commands::Proc { pid } => {
            cmd_proc(pid)?;
        }
        Commands::Asar(asar) => match asar.command {
            AsarSubcommand::List { file } => {
                cmd_asar_list(&file)?;
            }
            AsarSubcommand::Unpack { file, output } => {
                cmd_asar_unpack(&file, &output)?;
            }
        },
        Commands::Mcp => {
            let server = McpServer::new();
            server.run_stdio().await?;
        }
    }

    Ok(())
}
