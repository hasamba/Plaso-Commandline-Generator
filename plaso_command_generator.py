#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Plaso Command Line Generator for DFIR Investigations
=====================================================
An interactive script to generate optimal log2timeline, psort, and psteal commands
based on your investigation requirements.

Author: DFIR Specialist Tool
Version: 1.0.0
"""

import os
import sys
from datetime import datetime
from typing import Optional, List, Dict, Tuple


# =============================================================================
# CONFIGURATION DATA
# =============================================================================

PARSER_PRESETS = {
    "1": ("android", "Android devices"),
    "2": ("ios", "iOS devices (iPhone, iPad)"),
    "3": ("linux", "Linux systems"),
    "4": ("macos", "macOS systems"),
    "5": ("win7", "Windows 7/8/10/11 (recommended for Windows)"),
    "6": ("win7_slow", "Windows 7+ with ESE/MFT (slower, more thorough)"),
    "7": ("winxp", "Windows XP/2003"),
    "8": ("winxp_slow", "Windows XP with ESE/MFT (slower, more thorough)"),
    "9": ("webhist", "Web history artifacts only"),
    "10": ("mactime", "Bodyfile/mactime format"),
    "11": ("auto", "Auto-detect (let Plaso decide)"),
    "12": ("custom", "Custom parser selection"),
}

OUTPUT_FORMATS = {
    "1": ("dynamic", "Dynamic CSV (flexible fields) - Recommended"),
    "2": ("l2tcsv", "Legacy log2timeline CSV (17 fixed fields)"),
    "3": ("json", "JSON format"),
    "4": ("json_line", "JSON Lines format (one event per line)"),
    "5": ("xlsx", "Excel spreadsheet"),
    "6": ("tln", "TLN format (5 fields)"),
    "7": ("l2ttln", "Extended TLN format (7 fields)"),
    "8": ("kml", "KML format (for geo data)"),
    "9": ("opensearch", "OpenSearch database"),
    "10": ("opensearch_ts", "OpenSearch for Timesketch"),
    "11": ("null", "No output (for analysis only)"),
}

ANALYSIS_PLUGINS = {
    "1": ("browser_search", "Analyze browser search queries"),
    "2": ("chrome_extension", "Identify Chrome extensions"),
    "3": ("tagging", "Tag events using rule files"),
    "4": ("sessionize", "Group events by session"),
    "5": ("unique_domains_visited", "List unique domains visited"),
    "6": ("virustotal", "Check hashes against VirusTotal"),
    "7": ("viper", "Check hashes against Viper"),
    "8": ("bloom", "Check hashes against bloom filter"),
    "9": ("nsrlsvr", "Check hashes against NSRL server"),
}

HASHERS = {
    "1": ("md5", "MD5 hash"),
    "2": ("sha1", "SHA-1 hash"),
    "3": ("sha256", "SHA-256 hash"),
    "4": ("all", "All hashers (md5, sha1, sha256)"),
}

TAGGING_FILES = {
    "1": ("tag_windows.txt", "Windows tagging rules"),
    "2": ("tag_linux.txt", "Linux tagging rules"),
    "3": ("tag_macos.txt", "macOS tagging rules"),
    "4": ("custom", "Custom tagging file path"),
}

COMMON_TIMEZONES = [
    "UTC", "US/Eastern", "US/Central", "US/Mountain", "US/Pacific",
    "Europe/London", "Europe/Paris", "Europe/Berlin", "Asia/Tokyo",
    "Asia/Shanghai", "Australia/Sydney", "America/New_York",
]


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def print_banner():
    """Print the script banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    PLASO COMMAND LINE GENERATOR                              ║
║                    Digital Forensics & Incident Response                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This tool will guide you through creating optimal Plaso commands for your   ║
║  forensic investigation. Answer the questions to generate log2timeline,      ║
║  psort, and/or psteal command lines.                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_section(title: str):
    """Print a section header."""
    print(f"\n{'='*78}")
    print(f"  {title}")
    print(f"{'='*78}\n")


def print_menu(options: Dict, title: str = "Select an option:"):
    """Print a numbered menu."""
    print(f"\n{title}")
    print("-" * 50)
    for key, (value, description) in options.items():
        print(f"  [{key}] {value:<20} - {description}")
    print()


def get_input(prompt: str, default: str = None, required: bool = True) -> str:
    """Get user input with optional default value."""
    if default:
        prompt_text = f"{prompt} [{default}]: "
    else:
        prompt_text = f"{prompt}: "
    
    while True:
        response = input(prompt_text).strip()
        if not response and default:
            return default
        if response or not required:
            return response
        print("  ⚠ This field is required. Please enter a value.")


def get_yes_no(prompt: str, default: bool = False) -> bool:
    """Get yes/no response from user."""
    default_str = "Y/n" if default else "y/N"
    while True:
        response = input(f"{prompt} [{default_str}]: ").strip().lower()
        if not response:
            return default
        if response in ('y', 'yes'):
            return True
        if response in ('n', 'no'):
            return False
        print("  ⚠ Please enter 'y' or 'n'.")


def get_menu_choice(options: Dict, prompt: str = "Enter your choice") -> Tuple[str, str]:
    """Get a menu selection from user."""
    valid_choices = list(options.keys())
    while True:
        choice = input(f"{prompt}: ").strip()
        if choice in valid_choices:
            return options[choice]
        print(f"  ⚠ Invalid choice. Please select from: {', '.join(valid_choices)}")


def get_multi_choice(options: Dict, prompt: str = "Enter choices (comma-separated)") -> List[Tuple[str, str]]:
    """Get multiple menu selections from user."""
    valid_choices = list(options.keys())
    while True:
        response = input(f"{prompt}: ").strip()
        if not response:
            return []
        
        choices = [c.strip() for c in response.split(',')]
        if all(c in valid_choices for c in choices):
            return [options[c] for c in choices]
        
        invalid = [c for c in choices if c not in valid_choices]
        print(f"  ⚠ Invalid choice(s): {', '.join(invalid)}. Valid options: {', '.join(valid_choices)}")


def validate_path(path: str, must_exist: bool = True) -> bool:
    """Validate a file/directory path."""
    if must_exist:
        return os.path.exists(path)
    # For output files, check if parent directory exists
    parent = os.path.dirname(path)
    return not parent or os.path.exists(parent)


def validate_datetime(dt_str: str) -> bool:
    """Validate datetime string format."""
    formats = [
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
    ]
    for fmt in formats:
        try:
            datetime.strptime(dt_str.replace('+00:00', '').replace('Z', ''), fmt.replace('%z', ''))
            return True
        except ValueError:
            continue
    return False


# =============================================================================
# CONFIGURATION GATHERING
# =============================================================================

class PlasoConfig:
    """Configuration container for Plaso command generation."""
    
    def __init__(self):
        # Source configuration
        self.source_path: str = ""
        self.source_type: str = ""  # image, directory, file
        
        # Output configuration
        self.storage_file: str = ""
        self.output_file: str = ""
        self.output_format: str = "dynamic"
        self.output_timezone: str = "UTC"
        
        # Parser configuration
        self.parser_preset: str = "auto"
        self.custom_parsers: str = ""
        
        # Processing options
        self.process_vss: bool = False
        self.vss_stores: str = ""
        self.partitions: str = ""
        self.process_compressed: bool = True
        
        # Collection filters
        self.use_filter_file: bool = False
        self.filter_file: str = ""
        self.use_artifact_filters: bool = False
        self.artifact_filters: str = ""
        
        # Date/time filters
        self.use_date_filter: bool = False
        self.date_filter_start: str = ""
        self.date_filter_end: str = ""
        
        # Hashers
        self.enable_hashers: bool = True
        self.hashers: str = "sha256"
        
        # YARA
        self.use_yara: bool = False
        self.yara_rules_path: str = ""
        
        # Analysis plugins
        self.analysis_plugins: List[str] = []
        self.tagging_file: str = ""
        self.virustotal_api_key: str = ""
        
        # Event filter (for psort)
        self.event_filter: str = ""
        self.use_time_slice: bool = False
        self.time_slice_datetime: str = ""
        self.time_slice_size: int = 5
        
        # Performance options
        self.workers: int = 0  # 0 = auto
        self.single_process: bool = False
        self.buffer_size: int = 0
        self.process_memory_limit: int = 0
        
        # Logging
        self.log_file: str = ""
        self.debug_mode: bool = False
        
        # Output options
        self.include_all_events: bool = False
        self.dynamic_fields: str = ""
        self.use_dynamic_time: bool = True


def gather_source_config(config: PlasoConfig):
    """Gather source/evidence configuration."""
    print_section("SOURCE EVIDENCE CONFIGURATION")
    
    print("What type of source are you processing?")
    print("  [1] Storage media image (E01, raw, dd, etc.)")
    print("  [2] Directory / mount point")
    print("  [3] Single file")
    print()
    
    source_types = {"1": "image", "2": "directory", "3": "file"}
    while True:
        choice = get_input("Select source type (1-3)", "1")
        if choice in source_types:
            config.source_type = source_types[choice]
            break
        print("  ⚠ Please enter 1, 2, or 3.")
    
    while True:
        config.source_path = get_input("Enter the path to your source evidence")
        if validate_path(config.source_path):
            break
        print(f"  ⚠ Path does not exist: {config.source_path}")
    
    # Image-specific options
    if config.source_type == "image":
        print("\n--- Storage Media Image Options ---")
        
        if get_yes_no("Do you know the partition number to process?", False):
            config.partitions = get_input("Enter partition number(s) (e.g., '2' or '1,3' or 'all')", required=False)
        
        if get_yes_no("Process Volume Shadow Snapshots (VSS)?", False):
            config.process_vss = True
            config.vss_stores = get_input(
                "Enter VSS stores to process (e.g., '1,2,3' or '1..5' or 'all')",
                "all"
            )


def gather_output_config(config: PlasoConfig):
    """Gather output configuration."""
    print_section("OUTPUT CONFIGURATION")
    
    # Storage file
    default_storage = f"timeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.plaso"
    config.storage_file = get_input(
        "Enter the Plaso storage file path",
        default_storage
    )
    
    # Output file
    default_output = config.storage_file.replace('.plaso', '.csv')
    config.output_file = get_input(
        "Enter the output file path (for psort)",
        default_output
    )
    
    # Output format
    print_menu(OUTPUT_FORMATS, "Select output format:")
    format_choice = get_menu_choice(OUTPUT_FORMATS, "Enter format choice")
    config.output_format = format_choice[0]
    
    # Timezone
    print(f"\nCommon timezones: {', '.join(COMMON_TIMEZONES[:6])}")
    config.output_timezone = get_input(
        "Enter output timezone",
        "UTC"
    )
    
    # Dynamic output options
    if config.output_format == "dynamic":
        if get_yes_no("Use dynamic time formatting (preserves original precision)?", True):
            config.use_dynamic_time = True
        
        if get_yes_no("Customize output fields?", False):
            print("\nDefault fields: datetime,timestamp_desc,source,source_long,message,parser,display_name,tag")
            config.dynamic_fields = get_input(
                "Enter comma-separated field names",
                required=False
            )


def gather_parser_config(config: PlasoConfig):
    """Gather parser configuration."""
    print_section("PARSER CONFIGURATION")
    
    print("Parser presets help optimize extraction for specific operating systems.")
    print_menu(PARSER_PRESETS, "Select parser preset:")
    
    parser_choice = get_menu_choice(PARSER_PRESETS, "Enter preset choice")
    
    if parser_choice[0] == "auto":
        config.parser_preset = ""  # Let Plaso auto-detect
    elif parser_choice[0] == "custom":
        print("\nCommon parsers: winevtx, winreg, prefetch, lnk, mft, usnjrnl, sqlite, text/syslog")
        config.custom_parsers = get_input(
            "Enter comma-separated parser names",
            required=True
        )
    else:
        config.parser_preset = parser_choice[0]


def gather_filter_config(config: PlasoConfig):
    """Gather collection filter configuration."""
    print_section("COLLECTION FILTERS (Optional)")
    
    print("Collection filters allow targeted extraction (faster processing).")
    
    if get_yes_no("Use artifact-based collection filters?", False):
        config.use_artifact_filters = True
        print("\nExamples: WindowsEventLogSystem, BrowserHistory, WindowsRegistryFilesAndTransactionLogs")
        config.artifact_filters = get_input(
            "Enter comma-separated artifact names",
            required=True
        )
    
    elif get_yes_no("Use a YAML filter file for targeted collection?", False):
        config.use_filter_file = True
        config.filter_file = get_input("Enter path to filter file")


def gather_date_filter_config(config: PlasoConfig):
    """Gather date/time filter configuration."""
    print_section("DATE/TIME FILTERS (Optional)")
    
    if get_yes_no("Filter events by date range?", False):
        config.use_date_filter = True
        
        print("\nDate format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
        
        while True:
            config.date_filter_start = get_input(
                "Enter start date (events after this date)",
                required=False
            )
            if not config.date_filter_start or validate_datetime(config.date_filter_start):
                break
            print("  ⚠ Invalid date format. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
        
        while True:
            config.date_filter_end = get_input(
                "Enter end date (events before this date)",
                required=False
            )
            if not config.date_filter_end or validate_datetime(config.date_filter_end):
                break
            print("  ⚠ Invalid date format. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")


def gather_hasher_config(config: PlasoConfig):
    """Gather hasher configuration."""
    print_section("FILE HASHING (Optional)")
    
    if get_yes_no("Calculate file hashes during extraction?", True):
        config.enable_hashers = True
        print_menu(HASHERS, "Select hasher(s):")
        hasher_choice = get_menu_choice(HASHERS, "Enter hasher choice")
        
        if hasher_choice[0] == "all":
            config.hashers = "md5,sha1,sha256"
        else:
            config.hashers = hasher_choice[0]
    else:
        config.enable_hashers = False


def gather_yara_config(config: PlasoConfig):
    """Gather YARA configuration."""
    print_section("YARA SCANNING (Optional)")
    
    if get_yes_no("Scan files with YARA rules?", False):
        config.use_yara = True
        while True:
            config.yara_rules_path = get_input("Enter path to YARA rules file/directory")
            if validate_path(config.yara_rules_path):
                break
            print(f"  ⚠ Path does not exist: {config.yara_rules_path}")


def gather_analysis_config(config: PlasoConfig):
    """Gather analysis plugin configuration."""
    print_section("ANALYSIS PLUGINS (Optional)")
    
    print("Analysis plugins provide automated analysis and tagging of events.")
    
    if get_yes_no("Enable analysis plugins?", False):
        print_menu(ANALYSIS_PLUGINS, "Available analysis plugins (enter comma-separated numbers):")
        plugins = get_multi_choice(ANALYSIS_PLUGINS, "Enter plugin choices (or press Enter to skip)")
        
        config.analysis_plugins = [p[0] for p in plugins]
        
        # Tagging file
        if "tagging" in config.analysis_plugins:
            print_menu(TAGGING_FILES, "Select tagging file:")
            tag_choice = get_menu_choice(TAGGING_FILES, "Enter tagging file choice")
            
            if tag_choice[0] == "custom":
                config.tagging_file = get_input("Enter path to custom tagging file")
            else:
                config.tagging_file = tag_choice[0]
        
        # VirusTotal API key
        if "virustotal" in config.analysis_plugins:
            config.virustotal_api_key = get_input(
                "Enter VirusTotal API key",
                required=True
            )


def gather_event_filter_config(config: PlasoConfig):
    """Gather event filter configuration for psort."""
    print_section("EVENT FILTERING FOR OUTPUT (Optional)")
    
    print("Event filters allow you to filter the timeline output.")
    
    if get_yes_no("Use time slice (events around a specific timestamp)?", False):
        config.use_time_slice = True
        
        while True:
            config.time_slice_datetime = get_input(
                "Enter the timestamp of interest (ISO 8601 format: YYYY-MM-DDTHH:MM:SS)"
            )
            if validate_datetime(config.time_slice_datetime):
                break
            print("  ⚠ Invalid datetime format.")
        
        config.time_slice_size = int(get_input(
            "Enter time slice size in minutes (events before and after)",
            "5"
        ))
    
    elif get_yes_no("Use custom event filter expression?", False):
        print("\nFilter examples:")
        print("  - date > '2023-01-01' and date < '2023-12-31'")
        print("  - source_long contains 'Event Log'")
        print("  - data_type is 'windows:registry:key_value'")
        print("  - message contains 'login' and source is 'LOG'")
        print()
        config.event_filter = get_input("Enter filter expression")


def gather_performance_config(config: PlasoConfig):
    """Gather performance-related configuration."""
    print_section("PERFORMANCE OPTIONS (Optional)")
    
    if get_yes_no("Configure advanced performance options?", False):
        print("\nWorker processes (0 = auto-detect based on CPU cores):")
        workers = get_input("Number of worker processes", "0")
        config.workers = int(workers) if workers.isdigit() else 0
        
        if get_yes_no("Run in single-process mode (useful for debugging)?", False):
            config.single_process = True
        
        memory_limit = get_input(
            "Process memory limit in bytes (0 = no limit)",
            "0",
            required=False
        )
        config.process_memory_limit = int(memory_limit) if memory_limit.isdigit() else 0


def gather_logging_config(config: PlasoConfig):
    """Gather logging configuration."""
    print_section("LOGGING OPTIONS")
    
    if get_yes_no("Save logs to file?", True):
        default_log = config.storage_file.replace('.plaso', '.log.gz')
        config.log_file = get_input("Enter log file path", default_log)
    
    if get_yes_no("Enable debug mode (verbose logging)?", False):
        config.debug_mode = True


def gather_output_options(config: PlasoConfig):
    """Gather additional output options for psort."""
    print_section("ADDITIONAL OUTPUT OPTIONS")
    
    if get_yes_no("Include duplicate events in output?", False):
        config.include_all_events = True


# =============================================================================
# COMMAND GENERATION
# =============================================================================

def generate_log2timeline_command(config: PlasoConfig) -> str:
    """Generate log2timeline.py command."""
    cmd_parts = ["log2timeline.py"]
    
    # Storage file
    cmd_parts.append(f"--storage-file {config.storage_file}")
    
    # Parser configuration
    if config.custom_parsers:
        cmd_parts.append(f"--parsers '{config.custom_parsers}'")
    elif config.parser_preset:
        cmd_parts.append(f"--parsers {config.parser_preset}")
    
    # VSS options
    if config.process_vss and config.vss_stores:
        cmd_parts.append(f"--vss-stores {config.vss_stores}")
    elif not config.process_vss:
        cmd_parts.append("--vss-stores none")
    
    # Partition options
    if config.partitions:
        cmd_parts.append(f"--partitions {config.partitions}")
    
    # Collection filters
    if config.use_artifact_filters:
        cmd_parts.append(f"--artifact-filters '{config.artifact_filters}'")
    elif config.use_filter_file:
        cmd_parts.append(f"--file-filter {config.filter_file}")
    
    # Hashers
    if config.enable_hashers:
        cmd_parts.append(f"--hashers {config.hashers}")
    else:
        cmd_parts.append("--hashers none")
    
    # YARA
    if config.use_yara:
        cmd_parts.append(f"--yara-rules {config.yara_rules_path}")
    
    # Performance options
    if config.workers > 0:
        cmd_parts.append(f"--workers {config.workers}")
    
    if config.single_process:
        cmd_parts.append("--single-process")
    
    if config.process_memory_limit > 0:
        cmd_parts.append(f"--process-memory-limit {config.process_memory_limit}")
    
    # Logging
    if config.log_file:
        cmd_parts.append(f"--log-file {config.log_file}")
    
    if config.debug_mode:
        cmd_parts.append("--debug")
    
    # Source path (must be last)
    cmd_parts.append(config.source_path)
    
    return " \\\n    ".join(cmd_parts)


def generate_psort_command(config: PlasoConfig) -> str:
    """Generate psort.py command."""
    cmd_parts = ["psort.py"]
    
    # Output format
    cmd_parts.append(f"-o {config.output_format}")
    
    # Output file
    cmd_parts.append(f"-w {config.output_file}")
    
    # Timezone
    if config.output_timezone and config.output_timezone != "UTC":
        cmd_parts.append(f"--output-time-zone {config.output_timezone}")
    
    # Dynamic output options
    if config.output_format == "dynamic":
        if config.use_dynamic_time:
            cmd_parts.append("--dynamic-time")
        
        if config.dynamic_fields:
            cmd_parts.append(f"--fields '{config.dynamic_fields}'")
    
    # Include all events
    if config.include_all_events:
        cmd_parts.append("-a")
    
    # Analysis plugins
    if config.analysis_plugins:
        plugins_str = ",".join(config.analysis_plugins)
        cmd_parts.append(f"--analysis {plugins_str}")
        
        if "tagging" in config.analysis_plugins and config.tagging_file:
            cmd_parts.append(f"--tagging-file {config.tagging_file}")
        
        if "virustotal" in config.analysis_plugins and config.virustotal_api_key:
            cmd_parts.append(f"--virustotal-api-key {config.virustotal_api_key}")
    
    # Time slice
    if config.use_time_slice:
        cmd_parts.append(f"--slice '{config.time_slice_datetime}'")
        cmd_parts.append(f"--slice-size {config.time_slice_size}")
    
    # Storage file
    cmd_parts.append(config.storage_file)
    
    # Event filter
    if config.event_filter:
        cmd_parts.append(f'"{config.event_filter}"')
    elif config.use_date_filter:
        filters = []
        if config.date_filter_start:
            filters.append(f"date > '{config.date_filter_start}'")
        if config.date_filter_end:
            filters.append(f"date < '{config.date_filter_end}'")
        if filters:
            cmd_parts.append(f'"{" and ".join(filters)}"')
    
    return " \\\n    ".join(cmd_parts)


def generate_psteal_command(config: PlasoConfig) -> str:
    """Generate psteal.py command (combined log2timeline + psort)."""
    cmd_parts = ["psteal.py"]
    
    # Source
    cmd_parts.append(f"--source {config.source_path}")
    
    # Output
    cmd_parts.append(f"-o {config.output_format}")
    cmd_parts.append(f"-w {config.output_file}")
    
    # Parser preset
    if config.custom_parsers:
        cmd_parts.append(f"--parsers '{config.custom_parsers}'")
    elif config.parser_preset:
        cmd_parts.append(f"--parsers {config.parser_preset}")
    
    # VSS
    if config.process_vss and config.vss_stores:
        cmd_parts.append(f"--vss-stores {config.vss_stores}")
    
    # Hashers
    if config.enable_hashers:
        cmd_parts.append(f"--hashers {config.hashers}")
    
    # Log file
    if config.log_file:
        cmd_parts.append(f"--log-file {config.log_file}")
    
    return " \\\n    ".join(cmd_parts)


def generate_pinfo_command(config: PlasoConfig) -> str:
    """Generate pinfo.py command."""
    return f"pinfo.py -v {config.storage_file}"


# =============================================================================
# OUTPUT AND SUMMARY
# =============================================================================

def print_commands(config: PlasoConfig):
    """Print all generated commands."""
    
    print("\n")
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print("║                         GENERATED PLASO COMMANDS                             ║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    
    # Configuration summary
    print("\n" + "=" * 78)
    print("  CONFIGURATION SUMMARY")
    print("=" * 78)
    print(f"  Source:           {config.source_path}")
    print(f"  Source Type:      {config.source_type}")
    print(f"  Storage File:     {config.storage_file}")
    print(f"  Output File:      {config.output_file}")
    print(f"  Output Format:    {config.output_format}")
    print(f"  Parser Preset:    {config.parser_preset or 'auto-detect'}")
    print(f"  Hashers:          {config.hashers if config.enable_hashers else 'disabled'}")
    print(f"  VSS Processing:   {'Yes - ' + config.vss_stores if config.process_vss else 'No'}")
    if config.analysis_plugins:
        print(f"  Analysis Plugins: {', '.join(config.analysis_plugins)}")
    
    # Step 1: log2timeline
    print("\n" + "-" * 78)
    print("  STEP 1: EXTRACTION (log2timeline.py)")
    print("-" * 78)
    print("  Run this command first to extract events from the source:\n")
    print(generate_log2timeline_command(config))
    
    # Step 2: psort
    print("\n" + "-" * 78)
    print("  STEP 2: PROCESSING (psort.py)")
    print("-" * 78)
    print("  After extraction, run this command to sort, filter, and output events:\n")
    print(generate_psort_command(config))
    
    # Alternative: psteal
    print("\n" + "-" * 78)
    print("  ALTERNATIVE: QUICK TIMELINE (psteal.py)")
    print("-" * 78)
    print("  For a quick timeline with default options, use this single command:\n")
    print(generate_psteal_command(config))
    
    # Info command
    print("\n" + "-" * 78)
    print("  VIEW STORAGE INFO (pinfo.py)")
    print("-" * 78)
    print("  To inspect the storage file after extraction:\n")
    print(generate_pinfo_command(config))
    
    # Tips
    print("\n" + "=" * 78)
    print("  TIPS & NOTES")
    print("=" * 78)
    print("""
  • The extraction step (log2timeline) typically takes the longest time
  • Use psteal for quick triage; use log2timeline + psort for more control
  • Monitor memory usage with large images - consider --process-memory-limit
  • For very large images, consider using collection filters for targeted extraction
  • The .plaso storage file can be re-processed with different psort options
  • Use 'pinfo.py -v <storage_file>' to verify extraction results
  • For Timesketch integration, use the opensearch_ts output module
    """)


def save_commands_to_file(config: PlasoConfig):
    """Save generated commands to a shell script file."""
    if get_yes_no("\nSave commands to a shell script file?", False):
        script_path = get_input(
            "Enter script filename",
            f"plaso_commands_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sh"
        )
        
        script_content = f"""#!/bin/bash
# Plaso Command Script
# Generated: {datetime.now().isoformat()}
# Source: {config.source_path}

# =============================================================================
# STEP 1: EXTRACTION (log2timeline)
# =============================================================================
# Extracts events from the source evidence into a Plaso storage file

{generate_log2timeline_command(config)}

# =============================================================================
# STEP 2: PROCESSING (psort)
# =============================================================================
# Processes the storage file and outputs the timeline

{generate_psort_command(config)}

# =============================================================================
# ALTERNATIVE: QUICK TIMELINE (psteal)
# =============================================================================
# Uncomment to use psteal instead of the two-step process

# {generate_psteal_command(config)}

# =============================================================================
# VIEW STORAGE INFO
# =============================================================================
# Uncomment to view information about the storage file

# {generate_pinfo_command(config)}
"""
        
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        os.chmod(script_path, 0o755)
        print(f"\n  ✓ Commands saved to: {script_path}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Main entry point."""
    try:
        print_banner()
        
        config = PlasoConfig()
        
        # Gather all configuration
        gather_source_config(config)
        gather_output_config(config)
        gather_parser_config(config)
        gather_filter_config(config)
        gather_date_filter_config(config)
        gather_hasher_config(config)
        gather_yara_config(config)
        gather_analysis_config(config)
        gather_event_filter_config(config)
        gather_performance_config(config)
        gather_logging_config(config)
        gather_output_options(config)
        
        # Generate and display commands
        print_commands(config)
        
        # Optionally save to file
        save_commands_to_file(config)
        
        print("\n" + "=" * 78)
        print("  Command generation complete. Happy hunting!")
        print("=" * 78 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n  Operation cancelled by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
