 /////////////////////////////////////////////////////////////
 // Pretty Modular Symetric Encryption (PMSE)  
 //	PMSEv3.0 fast encryption version - revision 10/2023  //
 // This code has been developed by Etienne LEMAIRE         //
 // Published here: https://doi.org/10.48550/arXiv.1905.08150 //
  // Web demo of PMSE :  http://blocksnet.free.fr/PMSE/ 		//
 /////////////////////////////////////////////////////////////

#include <string.h>

/* Fast PMSE encryption function */
void pmse_encrypt(char *msg, int l_msg, char *pass, int l_pass, char *pass2, int l_pass2, char iv[6]){

int x0 = (int)iv[0];
int x1 = (int)iv[1];
int x2 = (int)iv[2];
int x3 = (int)iv[3];
char xt = iv[4], data =0, xa=0, xb=0, xc=0, xd=0;
int Yn = (int)iv[5];

int i=0;

    for ( i=0; i<l_msg ; i++){

        /////////////////////////////////////////
		// Bloc 1: Pseudo random byte generation
		//////////////////////////////////////////
          Yn = x2*i*i + x1*i + (Yn>>(x1&0x07));

          xa = (Yn & 0xFF000000)>>24 ;
          xb = (Yn & 0xFF0000)>>16 ;
          xc = (Yn & 0xFF00)>>8 ;
          xd = Yn & 0xFF;
          x0 = (xa^xb^xc^xd);

          x1 = pass[i % l_pass];
          x2 = pass2[(i+x1)%(l_pass2)];
          x3 = ((Yn>>3) + (xt<<1))&0xFF;
          xt = (x0^x1^x2^x3)&0xFF;

          if (xt==0){

            xt = i%iv[14];
            x0 = i%iv[15];
            x1 = i%iv[16];
            x2 = i%iv[17];
            x3 = i%iv[18];

          }
		  ////////////////////////////////////////
          /// BLOC2: data byte "desconstruction"
		  ////////////////////////////////////////
          data = msg[i];
          if ((xd & 0x03)==0){
                data = ((data&0x0F)<<4) + ((data&0xF0)>>4);
               // data = data^0xC0;
          }
          if ((xd & 0x03)==1){
                data = ((data&0x3F)<<2) + ((data&0xC0)>>6);
               // data = data^0x0A;
          }
          if ((xd & 0x03)==2){
                data = ((data&0x33)<<2) + ((data&0xCC)>>2);
               // data = data^0xA0;
          }
          if ((xd & 0x03)==3){
                data = ((data&0x1F)<<3) + ((data&0xE0)>>5);
               // data = data^0x0C;
          }

        //////////////////////////
		// BLOC3: XOR encryption
		///////////////////////////
          msg[i] = data^xt; // deconstructed byte XOR pseudo random key

    }

}


/* Fast PMSE decryption function */
void pmse_decrypt(char *msg, int l_msg, char *pass, int l_pass, char *pass2, int l_pass2, char iv[6]){

int x0 = (int)iv[0];
int x1 = (int)iv[1];
int x2 = (int)iv[2];
int x3 = (int)iv[3];
char xt = iv[4], data =0, xa=0, xb=0, xc=0, xd=0;
int Yn = (int)iv[5];

int i=0;

    for ( i=0; i<l_msg ; i++){

        /////////////////////////////////////////
		// Bloc 1: Pseudo random byte generation
		//////////////////////////////////////////
		  
          Yn = x2*i*i + x1*i + (Yn>>(x1&0x07));

          xa = (Yn & 0xFF000000)>>24 ;
          xb = (Yn & 0xFF0000)>>16 ;
          xc = (Yn & 0xFF00)>>8 ;
          xd = Yn & 0xFF;
          x0 = (xa^xb^xc^xd);

          x1 = pass[i % l_pass];
          x2 = pass2[(i+x1)%(l_pass2)];
          x3 = ((Yn>>3) + (xt<<1))&0xFF;
          xt = (x0^x1^x2^x3)&0xFF;

          if (xt==0){

            xt = i%iv[14];
            x0 = i%iv[15];
            x1 = i%iv[16];
            x2 = i%iv[17];
            x3 = i%iv[18];

          }
          data = msg[i];

        //////////////////////////
		// BLOC2: XOR decryption
		///////////////////////////
          data = data^xt; 

          ////////////////////////////////////////
          /// BLOC3: data byte "reconstruction"
		  ////////////////////////////////////////

          if ((xd & 0x03)==0){
                data = ((data&0x0F)<<4) + ((data&0xF0)>>4);
               // data = data^0xC0;
          }
          if ((xd & 0x03)==1){
                data = ((data&0xFC)>>2) + ((data&0x03)<<6);
               // data = data^0x0A;
          }
          if ((xd & 0x03)==2){
                data = ((data&0x33)<<2) + ((data&0xCC)>>2);
               // data = data^0xA0;
          }
          if ((xd & 0x03)==3){
                data = ((data&0xF8)>>3) + ((data&0x07)<<5);
               // data = data^0x0C;
          }

        msg[i]=data;
    }

}
