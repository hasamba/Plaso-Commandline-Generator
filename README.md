# Plaso Command Line Generator

An interactive Python tool for generating optimal [Plaso](https://plaso.readthedocs.io/) command lines for Digital Forensics & Incident Response (DFIR) investigations.

## Overview

This tool guides you through creating properly configured `log2timeline`, `psort`, and `psteal` commands based on your investigation requirements. Instead of memorizing complex command-line options, answer simple questions to generate optimized commands.

## Features

- **Interactive Configuration** - Step-by-step wizard for all Plaso options
- **Parser Presets** - Pre-configured parser sets for Windows, Linux, macOS, Android, iOS
- **Multiple Output Formats** - Dynamic CSV, JSON, Excel, TLN, KML, OpenSearch, and more
- **Collection Filters** - Artifact-based or YAML filter file support for targeted extraction
- **Date/Time Filtering** - Filter events by date range or time slice
- **File Hashing** - MD5, SHA-1, SHA-256 hash calculation
- **YARA Scanning** - Integrate YARA rules during extraction
- **Analysis Plugins** - Browser search analysis, Chrome extensions, tagging, VirusTotal integration
- **Volume Shadow Snapshots** - VSS processing for Windows images
- **Performance Tuning** - Worker processes, memory limits, single-process mode
- **Script Export** - Save generated commands to an executable shell script

## Requirements

- Python 3.6+
- [Plaso](https://plaso.readthedocs.io/en/latest/sources/user/Installation.html) installed on the target system

## Usage

```bash
python plaso_command_generator.py
```

Follow the interactive prompts to configure:

1. **Source Evidence** - Image file, directory, or single file
2. **Output Settings** - Storage file, output format, timezone
3. **Parsers** - OS-specific presets or custom parser selection
4. **Filters** - Collection filters and date ranges
5. **Hashing** - File hash algorithms
6. **Analysis** - Optional analysis plugins
7. **Performance** - Worker count and memory limits

## Generated Commands

The tool generates four commands:

| Command | Purpose |
|---------|---------|
| `log2timeline.py` | Extract events from source evidence |
| `psort.py` | Sort, filter, and output timeline |
| `psteal.py` | Combined extraction + output (quick mode) |
| `pinfo.py` | Inspect storage file metadata |

## Example Output

```bash
# STEP 1: EXTRACTION
log2timeline.py \
    --storage-file timeline_20250111.plaso \
    --parsers win7 \
    --vss-stores none \
    --hashers sha256 \
    /evidence/disk.E01

# STEP 2: PROCESSING
psort.py \
    -o dynamic \
    -w timeline_20250111.csv \
    --dynamic-time \
    timeline_20250111.plaso
```

## Parser Presets

| Preset | Description |
|--------|-------------|
| `android` | Android devices |
| `ios` | iOS devices (iPhone, iPad) |
| `linux` | Linux systems |
| `macos` | macOS systems |
| `win7` | Windows 7/8/10/11 (recommended) |
| `win7_slow` | Windows with ESE/MFT (thorough) |
| `winxp` | Windows XP/2003 |
| `webhist` | Web history artifacts only |

## Output Formats

- `dynamic` - Dynamic CSV with flexible fields (recommended)
- `l2tcsv` - Legacy log2timeline CSV (17 fixed fields)
- `json` / `json_line` - JSON formats
- `xlsx` - Excel spreadsheet
- `tln` / `l2ttln` - TLN formats
- `opensearch_ts` - OpenSearch for Timesketch

## License

MIT License

## Related Resources

- [Plaso Documentation](https://plaso.readthedocs.io/)
- [log2timeline Wiki](https://github.com/log2timeline/plaso/wiki)
- [DFIR Training](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/)
