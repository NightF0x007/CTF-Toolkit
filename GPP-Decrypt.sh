#!/bin/bash

# Function to display usage
usage() {
  echo "Usage: $0 -p <gpp password> -o <out file> [-h]"
  echo "  -p    Encrypted GPP Password"
  echo "  -o    Decrypted password output file"
  echo "  -h    Displays this help menu"
  exit 1
}

# The known AES key used by Microsoft for GPP encryption
AES_KEY='4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b'

run_decrypt() {
  # The encrypted GPP password
  local ENCRYPTED_PASSWORD="$1"
  local password_file="$2"
  # Convert the key and data from hex and base64, respectively
  BIN_KEY=$(echo $AES_KEY | xxd -r -p)
  BIN_DATA=$(echo $ENCRYPTED_PASSWORD | base64 -d)
  # Decrypt the password and save to file
  echo -n $BIN_DATA | openssl aes-256-cbc -d -A -iv 0 -K $BIN_KEY > "$password_file"
  echo "Decrypted password saved to $password_file"
}

# Main function
main() {
  # Parse command-line options
  while getopts "p:o:h" opt; do
    case ${opt} in
      p ) ENCRYPTED_PASSWORD=$OPTARG ;;
      o ) OUT_FILE=$OPTARG ;;
      h ) usage ;;
      ? ) usage ;;
    esac
  done

  # Verify required options are provided
  if [ -z "$ENCRYPTED_PASSWORD" ] || [ -z "$OUT_FILE" ]; then
    echo "Both -p (password) and -o (output file) options are required."
    usage
  fi

  # Run decryption
  run_decrypt "$ENCRYPTED_PASSWORD" "$OUT_FILE"
}

# Pass all arguments to the main function
main "$@"
