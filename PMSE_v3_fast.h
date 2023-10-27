
/////////////////////////////////////////////////////////////
 // Pretty Modular Symetric Encryption (PMSE)  
 //	PMSEv3.0 fast encryption version - revision 10/2023  //
 // This code has been developed by Etienne LEMAIRE         //
 // Published here: https://doi.org/10.48550/arXiv.1905.08150 //
 /////////////////////////////////////////////////////////////

#include <string.h>


/* Fast PMSE encryption function */
void pmse_encrypt(char *msg, int l_msg, char *pass, int l_pass, char *pass2, int l_pass2, char iv[24]);



/* Fast PMSE encryption function */
void pmse_decrypt(char *msg, int l_msg, char *pass, int l_pass, char *pass2, int l_pass2, char iv[24]);