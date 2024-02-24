#!/bin/bash

# Initial setup and default values
RUN_NMAP=1
RUN_DIR=1
RUN_SMB=1
TARGET=""
CTF_DIR=""
DIR_WORDLIST=""

# Function to display usage
usage() {
    echo "Usage: $0 -t <target> -o <ctf_directory> [-w /path/to/wordlist.txt] [-n] [-d] [-s] [-h]"
    echo "  -t    Target IP address"
    echo "  -o    CTF directory for output"
    echo "  -w    Wordlist for directory search"
    echo "  -n    Skip Nmap scan"
    echo "  -d    Skip Directory enumeration"
    echo "  -s    Skip SMB enumeration"
    echo "  -h    Displays this help menu"
    exit 1
}

# Function to validate IP address format
validate_ip() {
    if [[ ! $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Invalid IP address format: $1"
        exit 1
    fi
}

# Function to run Directory enumeration with Gobuster
run_dir_enum() {
    if [ ! -f "$DIR_WORDLIST" ]; then
        echo "Directory search wordlist not found: $DIR_WORDLIST"
        exit 1
    fi

    local dir_enum_out="$CTF_DIR/dir_enum/results.txt"
    echo "Running Directory search..."
    gobuster dir -u "http://$TARGET" -w "$DIR_WORDLIST" -o "$dir_enum_out"
    if [ $? -ne 0 ]; then
        echo "Directory search encountered an error."
        exit 1
    fi
    echo "Directory search output saved to $dir_enum_out"
}

# Function to setup directories
setup_directories() {
    mkdir -p "$CTF_DIR"/{nmap,dir_enum,smb}
    echo "Directories for Nmap, Directory enumeration, and SMB created under $CTF_DIR"
}

# Function to run Nmap
run_nmap() {
    local nmap_out="$CTF_DIR/nmap/summary.txt"
    echo "Running Nmap..."
    nmap -p- -Pn --max-retries 2 -sCV -T4 "$TARGET" | tee "$CTF_DIR/nmap/nmap_full_output.txt"
    grep -E "open|filtered" "$CTF_DIR/nmap/nmap_full_output.txt" > "$nmap_out"
    echo "Nmap output saved to $nmap_out"
}

# Function to run SMB enumeration
run_smb() {
    local smb_out="$CTF_DIR/smb/enum.txt"
    echo "Running SMB enumeration..."
    enum4linux -a "$TARGET" > "$smb_out"
    echo "SMB enumeration output saved to $smb_out"
}

# clean up function
cleanup() {
  echo "Cleaning up...."
}

# Trap for cleanup
trap 'cleanup' INT EXIT

# Main function with IP validation and setup
main() {
    # Parse command-line options
    while getopts "t:o:w:n:d:s:h" opt; do
        case ${opt} in
            t ) TARGET=$OPTARG ;;
            o ) CTF_DIR=$OPTARG ;;
            w ) DIR_WORDLIST=$OPTARG ;;
            n ) RUN_NMAP=0 ;;
            d ) RUN_DIR=0 ;;
            s ) RUN_SMB=0 ;;
            h ) usage ;;
        esac
    done
    
    shift $((OPTIND -1))
    
    if [ -z "$TARGET" ] || [ -z "$CTF_DIR" ]; then
        echo "Error: Target and CTF directory must be specified."
        usage
    fi

    validate_ip "$TARGET"
    setup_directories
    [ "$RUN_NMAP" -eq 1 ] && run_nmap
    [ "$RUN_DIR" -eq 1 ] && [ -z "$DIR_WORDLIST" ] && { echo "Error: Wordlist must be specified for directory enumeration."; exit 1; }
    [ "$RUN_SMB" -eq 1 ] && run_smb
    echo "Recon complete! Check the $CTF_DIR directory for output."
}

# Start the main function
main
