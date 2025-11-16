# Solana Program Sync

Download and analyze Solana BPF programs from mainnet.

## Quick Start

### 1. Setup

The tool will automatically create a `.env` file with the default mainnet RPC endpoint on first run:

```bash
RPC_ENDPOINT=https://api.mainnet-beta.solana.com
```

To use a custom RPC endpoint, edit the `.env` file before running sync.

### 2. Build

```bash
cargo build --release
```

### 3. Sync Programs

Download all programs from mainnet:

```bash
program-sync sync
```

This will:
- Fetch all BPF programs from the specified loaders (default: v1, v2, v3)
- Store metadata in `solana_programs.db`
- Download program binaries to `programs/` directory
- Track deployment slots for incremental updates

On subsequent runs, only new or updated programs are downloaded.

### 4. Analyze Programs

Query sBPF instructions across all downloaded programs:

```bash
# Count all call instructions
program-sync analyze --opcode call --count

# Show distribution of src registers for call instructions
program-sync analyze --opcode call --agg src

# Count sub32 instructions where imm=1
program-sync analyze --opcode sub32 --count imm=1

# Count add64 with multiple filters
program-sync analyze --opcode add64 --count src=1,dst=2
```

## Commands

### `sync` - Download Programs

Fetch programs from Solana RPC and save their binaries locally.

```bash
program-sync sync [OPTIONS]
```

**Options:**
- `--loader <VERSION>` - Loader version (1-4), repeatable
- `--rpc-url <URL>` - Custom RPC endpoint
- `--verbose, -v` - Log skipped/errored programs
- `--help, -h` - Show help

**Loader Versions:**
- `1` - BPFLoader v1
- `2` - BPFLoader v2
- `3` - BPFLoaderUpgradeable (most common)
- `4` - LoaderV4 (experimental)

**Examples:**

```bash
# Sync only BPFLoaderUpgradeable programs
program-sync sync --loader 3

# Sync multiple loaders
program-sync sync --loader 2 --loader 3

# Use custom RPC
program-sync sync --rpc-url https://my-rpc.com --verbose
```

### `analyze` - Query Instructions

Analyze sBPF instructions across all downloaded programs.

```bash
program-sync analyze --opcode <OPCODE> [OPTIONS]
```

**Options:**
- `--opcode <OPCODE>` - sBPF opcode to analyze (required)
- `--agg <FIELD>` - Aggregate and show distribution by field (`src`, `dst`, `imm`, `off`)
- `--count [FILTERS]` - Count matching instructions (optionally with filters)
- `--dir <PATH>` - Program directory (default: `programs`)
- `--help, -h` - Show help

**Examples:**

```bash
# Distribution of destination registers for add64
program-sync analyze --opcode add64 --agg dst

# Count jeq instructions with specific offset
program-sync analyze --opcode jeq --count off=10

# Show all opcodes (aggregate by opcode field - not yet implemented)
program-sync analyze --opcode mov64 --agg imm
```

## Database Schema

SQLite database at `solana_programs.db`:

```sql
CREATE TABLE programs (
    pubkey TEXT PRIMARY KEY,
    lamports INTEGER NOT NULL,
    loader_version INTEGER NOT NULL,
    is_closed INTEGER NOT NULL,
    last_updated_slot INTEGER NOT NULL,
    derived_executable_pubkey TEXT
);
```

**Fields:**
- `pubkey` - Program account public key
- `loader_version` - Loader version (1-4)
- `is_closed` - 1 if program is closed, 0 if active
- `last_updated_slot` - Deployment slot (for incremental updates)
- `derived_executable_pubkey` - ProgramData account address (for BPFUpgradeable)

## Output

```
solana_programs.db          # SQLite database
programs/
  ├── <pubkey1>.so          # Program binary (ELF)
  ├── <pubkey2>.so
  └── ...
```

## Environment Variables

- `RPC_ENDPOINT` - Solana RPC URL

A `.env` file is automatically created with the default mainnet RPC on first run. To use a custom RPC, edit `.env`:

```bash
# .env
RPC_ENDPOINT=https://your-custom-rpc.com
```

## Example Analysis Output

```
sBPF Instruction Analyzer
============================================================
Found 14975 .so files to analyze
Analyzing opcode: add64

============================================================
ANALYSIS RESULTS
============================================================
Files processed:       14973
Files with errors:     2
Total add64 instructions: 51044156

add64 instruction dst field distribution:
------------------------------------------------------------
DST             Count           Percentage
------------------------------------------------------------
0               484774          0.95          %
1               24480449        47.96         %
2               12333543        24.16         %
3               3368742         6.60          %
...
```
