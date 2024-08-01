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

# Function to setup directories
setup_directories() {
  if [ ! -d "$CTF_DIR" ] || [ -z "$CTF_DIR" ]; then
    mkdir -p "$CTF_DIR"/{nmap,dir_enum,smb}
  fi
  echo "Directories for Nmap, Directory enumeration, and SMB created under $CTF_DIR"
}

# Function to run Nmap and extracting ports
run_nmap() {
  local nmap_out="$CTF_DIR/nmap/nmap_summary.txt"
  echo "Running Nmap..."
  nmap -p- -Pn --min-rate 1000 --max-retries 1 -sCV -T4 -v -oG "$nmap_out" "$TARGET" | tee "$CTF_DIR/nmap/nmap_full_output.txt"
  echo "Nmap output saved to $nmap_out"

  # Identify SMB Port
  local smb_ports=$(grep -oP '445/open' $nmap_out | awk -F '/' '{print $1}')
  for port in $smb_ports; do
    run_smb
  done
  
  # Extract Web Ports
  local web_ports=$(grep -oP '\d{1,5}/open/tcp//http' $nmap_out | awk -F '/' '{print $1}' | grep -vE '21|22|23|25|53|135|139|445|161|110|143|3306|3389|5986')
  
  if [ -z "$DIR_WORDLIST" ]; then
    echo "Directory search wordlist not specified. Skipping directory brute-force."
    return
  fi

  for port in $web_ports; do
    run_dir_enum "$port"
  done
}

# Function to run SMB enumeration
run_smb() {
  local smb_out="$CTF_DIR/smb/enum.txt"
  echo "Running SMB enumeration..."
  enum4linux-ng -A "$TARGET" | tee "$smb_out"
  echo "SMB enumeration output saved to $smb_out"
}

# Function to run Directory enumeration with Gobuster
run_dir_enum() {
  local port=$1
  local dir_enum_out="$CTF_DIR/dir_enum/results_port_$port.txt"
  if [ ! -f "$DIR_WORDLIST" ]; then
    echo "Directory search wordlist not found: $DIR_WORDLIST"
    exit 1
  fi
  
  echo "Running Directory search on port $port..."
  gobuster dir -u "http://$TARGET:$port" -w "$DIR_WORDLIST" -q -t 50 -o "$dir_enum_out" -b 400-404
  if [ $? -ne 0 ]; then
    echo "Directory search encountered an error."
    return
  fi
  echo "Directory search output for $port saved to $dir_enum_out"
}

# clean up function
cleanup() {
  echo "Cleaning up...."
  exit 0
}

# Trap for cleanup
trap cleanup SIGINT
trap cleanup SIGTERM
trap cleanup SIGHUP

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
      ? ) usage ;;
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
  [ "$RUN_SMB" -eq 1 ]
  echo "Recon complete! Check the $CTF_DIR directory for output."
}

# Start the main function
main "$@"
