# PMSE
Pretty Modular Symetric Encryption (PMSE) - C version

PMSE (Pretty Modular Symetric Encryption) use 1 or 2 passwords in order to create a pseudo-random key as long as the message to be encrypted, including data deconstruction and reconstruction. Encryption method tested with image encryption tends to the entropy obtained with One-Time-Pad encryption (cf. https://doi.org/10.48550/arXiv.1905.08150 ). This C version is pretty fast and well suited for 8-bits microcontrollers.


Algorithm of PMSE (pseudo-script):

for (i=0; i.. message.length; i++){

 // Pseudo random byte generation		
    // polynomial order 1 or 2  (params: order, b_ and div_)        
    Yn = x2*i*i + b_*x1*i + Yn>>div_; 
		
	xa = (Yn & 0xFF000000)>>24 ;
	xb = (Yn & 0xFF0000)>>16 ;
	xc = (Yn & 0xFF00)>>8 ;
	xd = Yn & 0xFF;
	x0 = (xa^xb^xc^xd); //x0 ~> "crc8" of Yn
				
	x1 =  password[i % password.length]; // simple itterative selection of password char
	x2 =  login[x1 % login.length]; // char selection depanding on x1
	x3 = (i*x1 - x3*x2)%255; // x3 depends on i, x1, x2 and from previous x3
	xt = (xt^x0^x1^x2^x3)&0xFF;  // pseudo-random key for xor encryption, depends on x0, x1, x2, x3 and previous xt
		
		if (xt==0){
			// reinit of the algo with IV values
			x0=i%iv(0); x1=i%iv(1); x2=i%iv(2); x3=i%iv(3); xt=i%iv(4); Yn = i%iv(5);
		}
		
 // reversible bit switching (several permuation and complementation cases varying with params)
	message_swapped[i] = bit_switching(message[i]);	

 // XOR encryption
	crypt = (message_swapped[i] ^ xt )&0xFF; 

}
