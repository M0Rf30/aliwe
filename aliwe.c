/*
 *  _______  __  __
 * |   _   ||  ||__|.--.--.--..-----.
 * |.  1   ||  ||  ||  |  |  ||  -__|
 * |.  _   ||__||__||________||_____|
 * |:  |   |
 * |::.|:. |
 * `--- ---'
 *
 *  Program to generate WPA key for AGPF Alice Routers.
 *  Coded by Gianluca Boiano.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
 *  02110-1301, USA.
 */

#include <malloc.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define constants for various lengths and dimensions used in the program
#define MAX_ENTRIES 400
#define COLUMN_LENGTH 32
#define SSID_LENGTH 8
#define THREE_DIGIT_LENGTH 3
#define SERIAL_NUMBER_LENGTH 5
#define KEY_DIMENSION 2
#define QUERY_DIMENSION 8
#define MAC_ADDRESS_LENGTH 6
#define COMP_MAC_LENGTH 12
#define COMP_SERIAL_NUMBER_LENGTH 13
#define ALIAS_LENGTH 32
#define WPA_KEY_LENGTH 24
#define NUM_PADS 3
#define SUBSTR_LENGTH 7

// Predefined alias used in WPA key generation
unsigned char ALIAS[ALIAS_LENGTH] = {
    0x64, 0xC6, 0xDD, 0xE3, 0xE5, 0x79, 0xB6, 0xD9, 0x86, 0x96, 0x8D,
    0x34, 0x45, 0xD2, 0x3B, 0x15, 0xCA, 0xAF, 0x12, 0x84, 0x02, 0xAC,
    0x56, 0x00, 0x05, 0xCE, 0x20, 0x75, 0x91, 0x3F, 0xDC, 0xE8};

// Character set used for generating WPA keys
unsigned char initial_charset[256] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e',
    'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b',
    'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
    'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
    'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3'};

// Global variable to hold the application name
char *application_name;

// Structure to hold router data
struct RouterData {
  int three_digit_code;                  // Three-digit code for the router
  int serial_number;                     // Serial number of the router
  int key;                               // Key used for WPA generation
  int query;                             // Query value for WPA generation
  char mac_address[MAC_ADDRESS_LENGTH];  // MAC address of the router
};
typedef struct RouterData RouterInfo;

// Structure to hold WPA results
struct WPAResults {
  unsigned char
      mac_with_padding[MAC_ADDRESS_LENGTH];  // MAC address with padding
  char wpa_key[WPA_KEY_LENGTH];              // Generated WPA key
};
typedef struct WPAResults WPAResult;

// Function prototypes
void display_usage(void);
void display_models(char model_list[][COLUMN_LENGTH], int count);
int read_config(char model_list[][COLUMN_LENGTH],
                RouterInfo router_info[MAX_ENTRIES]);
int find_matching_entries(RouterInfo router_info[MAX_ENTRIES], int count,
                          long int ssid);
void generate_mac_from_ssid(char mac[MAC_ADDRESS_LENGTH], long int ssid,
                            WPAResult results[NUM_PADS]);
void generate_wpa_hash(unsigned char alias[ALIAS_LENGTH],
                       char serial_number[COMP_SERIAL_NUMBER_LENGTH],
                       unsigned char mac_with_padding[MAC_ADDRESS_LENGTH],
                       char wpa_key[WPA_KEY_LENGTH]);
void display_results(WPAResult results[NUM_PADS], long int ssid,
                     char serial_number[COMP_SERIAL_NUMBER_LENGTH]);

// Main function
int main(int argc, char *argv[]) {
  int i;

  RouterInfo router_info[MAX_ENTRIES];  // Array to hold router information
  char model_list[MAX_ENTRIES][COLUMN_LENGTH];  // Array to hold model names
  int model_count, found_entries = 0;  // Counters for models and found entries
  long int ssid;                       // Variable to hold the SSID
  char *endptr;                        // Pointer for string conversion
  application_name = argv[0];          // Set application name

  // Process command line arguments
  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-h")) {  // Help option
      display_usage();
      return 0;
    } else if (!strcmp(argv[i], "-r")) {  // Read config option
      model_count =
          read_config(model_list, router_info);  // Read router data from config
      if (model_count != -1) {
        printf("%d entry in <config> file\n\n", model_count + 1);
        display_models(model_list, model_count);  // Display models
        exit(0);
      } else {
        printf("<config> file not found or inaccessible\n");
      }
    } else if (!strcmp(argv[i], "-s")) {  // SSID option
      if (i + 1 >= argc) {                // Check for missing argument
        fprintf(stderr, "%s: missing argument\n", application_name);
        return -1;
      }
      if (strlen(argv[i + 1]) != SSID_LENGTH) {  // Validate SSID length
        fprintf(stderr, "%s: Please type 8 SSID digits\n", application_name);
        return -1;
      }
      model_count =
          read_config(model_list, router_info);  // Read router data from config
      if (model_count != 0) {
        printf("%d entry in <config> file\n\n", model_count + 1);
        ssid = strtol(argv[i + 1], &endptr,
                      10);  // Convert SSID from string to long
        found_entries = find_matching_entries(router_info, model_count,
                                              ssid);  // Find matching entries
      }

      if (found_entries == -1) {  // No matching entries found
        printf(
            "No entry found in <config> file\nReasons:\n\t*Your "
            "Alice router isn't an AGPF model\n\t*Your <config> "
            "file isn't updated\n\t*Did you write digits only?\n");
        return -1;
      } else {
        printf("\n%d entries found\n",
               found_entries);  // Display number of found entries
      }
      return 0;
    }
  }
  fprintf(stderr, "%s: missing argument\ttype -h for help\n",
          application_name);  // Error for missing argument
  return 0;
}

// Function to display usage information
void display_usage(void) {
  fprintf(stderr,
          "\nAliwe   ---  A WPA passphrase generator for AGPF Alice routers\n");
  fprintf(stderr, "usage: aliwe [<opts>]\n");
  fprintf(stderr, "  <opts>  -h                       print this message\n");
  fprintf(stderr,
          "          -r                       read from <config> "
          "file and print on console\n");
  fprintf(stderr,
          "          -s  <SSID digits>        WPA passphrase "
          "generation based on SSID digits\n");
  fprintf(stderr, "\n\nCoded by Gianluca Boiano  -  v0.2.1\n");
}

// Function to read router configuration from a file
int read_config(char model_list[][COLUMN_LENGTH],
                RouterInfo router_info[MAX_ENTRIES]) {
  int j, i = 0, t;
  char *temp;
  char *endptr;
  FILE *fp;
  fp = fopen("/usr/share/aliwe/config.txt",
             "r");  // Open config file for reading
  if (fp != NULL) {
    while (!feof(fp) &&
           i < MAX_ENTRIES) {           // Read until end of file or max entries
      fscanf(fp, "%s", model_list[i]);  // Read model name
      i++;
    }

    fclose(fp);  // Close the file

    // Process each model entry
    for (j = 0; j <= i; j++) {
      if (strlen(model_list[j]) == 30) {         // Check for specific length
        temp = (char *)calloc(1, sizeof(char));  // Allocate memory for temp
        temp[0] = model_list[j][11];             // Extract key
        router_info[j].key = strtol(temp, &endptr, 10);  // Convert to integer
        free(temp);  // Free allocated memory

        // Extract three-digit code
        temp = (char *)calloc(THREE_DIGIT_LENGTH, sizeof(char));
        for (t = 0; t < THREE_DIGIT_LENGTH; t++) {
          temp[t] = model_list[j][t + 1];
        }
        router_info[j].three_digit_code = strtol(temp, &endptr, 10);
        free(temp);

        // Extract serial number
        temp = (char *)calloc(SERIAL_NUMBER_LENGTH, sizeof(char));
        for (t = 0; t < SERIAL_NUMBER_LENGTH; t++) {
          temp[t] = model_list[j][t + 5];
        }
        router_info[j].serial_number = strtol(temp, &endptr, 10);
        free(temp);

        // Extract query value
        temp = (char *)calloc(QUERY_DIMENSION, sizeof(char));
        for (t = 0; t < QUERY_DIMENSION; t++) {
          temp[t] = model_list[j][t + 13];
        }
        router_info[j].query = strtol(temp, &endptr, 10);
        free(temp);

        // Extract MAC address
        for (t = 0; t < MAC_ADDRESS_LENGTH; t++) {
          router_info[j].mac_address[t] = model_list[j][t + 22];
        }
      } else {
        // Process entries of different length
        temp = (char *)calloc(KEY_DIMENSION, sizeof(char));
        for (t = 0; t < KEY_DIMENSION; t++) {
          temp[t] = model_list[j][t + 11];
        }
        router_info[j].key = strtol(temp, &endptr, 10);
        free(temp);

        // Extract three-digit code
        temp = (char *)calloc(THREE_DIGIT_LENGTH, sizeof(char));
        for (t = 0; t < THREE_DIGIT_LENGTH; t++) {
          temp[t] = model_list[j][t + 1];
        }
        router_info[j].three_digit_code = strtol(temp, &endptr, 10);
        free(temp);

        // Extract serial number
        temp = (char *)calloc(SERIAL_NUMBER_LENGTH, sizeof(char));
        for (t = 0; t < SERIAL_NUMBER_LENGTH; t++) {
          temp[t] = model_list[j][t + 5];
        }
        router_info[j].serial_number = strtol(temp, &endptr, 10);
        free(temp);

        // Extract query value
        temp = (char *)calloc(QUERY_DIMENSION, sizeof(char));
        for (t = 0; t < QUERY_DIMENSION; t++) {
          temp[t] = model_list[j][t + 14];
        }
        router_info[j].query = strtol(temp, &endptr, 10);
        free(temp);

        // Extract MAC address
        for (t = 0; t < MAC_ADDRESS_LENGTH; t++) {
          router_info[j].mac_address[t] = model_list[j][t + 23];
        }
      }
    }

    return i;  // Return the number of entries read
  } else {
    return -1;  // Return error if file not found
  }
}

// Function to display the list of models
void display_models(char model_list[][COLUMN_LENGTH], int count) {
  int i;
  for (i = 0; i < count; i++) {
    printf("%s\n", model_list[i]);  // Print each model
  }
}

// Function to find matching router entries based on SSID
int find_matching_entries(RouterInfo router_info[MAX_ENTRIES], int count,
                          long int ssid) {
  int i, temp, j = 0, z;
  char *buffer;
  WPAResult results[NUM_PADS];  // Array to hold WPA results

  temp = (int)ssid / 100000;  // Extract the three-digit code from SSID

  // Count matching entries
  for (i = 0; i < count; i++) {
    if (router_info[i].three_digit_code == temp) j++;
  }
  if (j == 0) {
    return -1;  // No matching entries found
  } else {
    printf("\nSummary for Alice-%ld:\n\n", ssid);

    // Process each matching entry
    for (i = 0; i < count; i++) {
      if (router_info[i].three_digit_code == temp) {
        buffer = (char *)calloc(
            13, sizeof(char));  // Allocate buffer for serial number
        sprintf(buffer, "%dX%07ld", router_info[i].serial_number,
                (ssid - router_info[i].query) /
                    router_info[i].key);  // Format serial number
        printf("\nSerial Number:");
        printf("\n%s\n\n", buffer);
        printf(
            "For this SN you can have these MACs\t\tand relative "
            "keys:\n");
        generate_mac_from_ssid(router_info[i].mac_address, ssid,
                               results);  // Generate MACs
        for (z = 0; z < NUM_PADS; z++) {
          generate_wpa_hash(ALIAS, buffer, results[z].mac_with_padding,
                            results[z].wpa_key);  // Generate WPA keys
        }

        display_results(results, ssid, buffer);  // Display results
      }
    }
  }

  return j;  // Return the number of matching entries
}

// Function to generate MAC addresses based on SSID
void generate_mac_from_ssid(char mac[MAC_ADDRESS_LENGTH], long int ssid,
                            WPAResult results[NUM_PADS]) {
  int z, a, i, j, ssid_cycle;
  int byte;

  // Complete MAC in string format
  char complete_mac[COMP_MAC_LENGTH];

  // Second part of the MAC generated from the SSID, not normalized
  char substr_mac[SUBSTR_LENGTH + 2];

  // Second part of the MAC generated from the SSID, normalized
  char substr_mac_normalized[SUBSTR_LENGTH];

  // MAC converted to bytes
  unsigned char cmp_mac_byte[MAC_ADDRESS_LENGTH];

  for (z = 0; z < NUM_PADS; z++) {
    ssid_cycle = ssid + (100000000 * z);  // Cycle through SSID for padding

    // Conversion from SSID to second part of MAC in string format
    sprintf(substr_mac, "%2X", ssid_cycle);

    j = 0;
    for (i = 1; i < SUBSTR_LENGTH; i++) {
      substr_mac_normalized[j] = substr_mac[i];  // Normalize the substring
      j++;
    }
    strcpy(complete_mac, mac);                    // Copy original MAC
    strcat(complete_mac, substr_mac_normalized);  // Append normalized substring

    j = 0;
    for (a = 0; a < COMP_MAC_LENGTH; a++) {
      /* Convert every 2 characters of the complete_mac string to an integer,
      then convert the integer to hexadecimal and map it to 1 byte
      */
      sscanf(&complete_mac[a], "%02x", &byte);  // Convert to byte
      cmp_mac_byte[j] = (unsigned char)byte;    // Store byte
      j++;
      a++;
    }

    memcpy(results[z].mac_with_padding, cmp_mac_byte,
           MAC_ADDRESS_LENGTH * sizeof(unsigned char));  // Store result
  }
}

// Function to generate the WPA hash based on the input parameters
void generate_wpa_hash(unsigned char alias[ALIAS_LENGTH],
                       char serial_number[COMP_SERIAL_NUMBER_LENGTH],
                       unsigned char mac_with_padding[MAC_ADDRESS_LENGTH],
                       char wpa_key[WPA_KEY_LENGTH]) {
  unsigned char hash[EVP_MAX_MD_SIZE];  // Buffer for the hash
  unsigned int hash_length;             // Length of the generated hash
  int i, hex_to_index;

  // Create a new context for SHA-256 hashing
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    fprintf(stderr, "Error creating EVP_MD_CTX\n");
    exit(EXIT_FAILURE);
  }

  // Initialize the SHA-256 context
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
    fprintf(stderr, "Error initializing digest\n");
    EVP_MD_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  // Update the context with the data to hash
  EVP_DigestUpdate(ctx, alias, ALIAS_LENGTH);
  EVP_DigestUpdate(ctx, serial_number, strlen(serial_number));
  EVP_DigestUpdate(ctx, mac_with_padding, MAC_ADDRESS_LENGTH);

  // Finalize the digest to produce the hash
  if (EVP_DigestFinal_ex(ctx, hash, &hash_length) != 1) {
    fprintf(stderr, "Error finalizing digest\n");
    EVP_MD_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  // Clean up the context
  EVP_MD_CTX_free(ctx);

  // Convert the hash to a WPA key using the predefined character set
  for (i = 0; i < WPA_KEY_LENGTH; i++) {
    hex_to_index = (int)hash[i];                 // Map hash value to index
    wpa_key[i] = initial_charset[hex_to_index];  // Map hash value to character
  }
}

// Function to display the generated WPA results
void display_results(WPAResult results[NUM_PADS], long int ssid,
                     char serial_number[COMP_SERIAL_NUMBER_LENGTH]) {
  int i, j, z;
  for (i = 0; i < NUM_PADS; i++) {
    printf("\nwith pad %d:\t", i);  // Display pad number
    for (j = 0; j < MAC_ADDRESS_LENGTH; j++) {
      printf("%02X", results[i].mac_with_padding[j]);  // Display MAC address
    }
    printf("\t\t\t", results[i].wpa_key);
    for (z = 0; z < WPA_KEY_LENGTH; z++) {
      printf("%c", results[i].wpa_key[z]);  // Display WPA key
    }
    printf("\n");
  }
}
