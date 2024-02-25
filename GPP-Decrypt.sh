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
  local ENCRYPTED_PASSWORD="$1"
  local password_file="$2"

  # Convert the key from hex and ensure it's the correct length
  if [ "${#AES_KEY}" -ne 64 ]; then
    echo "Invalid AES key length."
    exit 2
  fi
  BIN_KEY=$(echo $AES_KEY | xxd -r -p)

  # Validate and decode the encrypted password
  if ! BIN_DATA=$(echo $ENCRYPTED_PASSWORD | base64 -d 2>/dev/null); then
    echo "Base64 decoding failed. Ensure the encrypted password is base64 encoded."
    exit 3
  fi

  # Decrypt the password and handle potential decryption errors
  if ! DECRYPTED_PASSWORD=$(echo -n $BIN_DATA | openssl aes-256-cbc -d -A -iv 00000000000000000000000000000000 -K $BIN_KEY 2>/dev/null); then
    echo "AES decryption failed. Check the encrypted data and the AES key."
    exit 4
  fi

  echo "$DECRYPTED_PASSWORD" > "$password_file"
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
