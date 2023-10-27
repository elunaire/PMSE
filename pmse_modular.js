/////////////////////////////////////////////////////////////////////
//      Pretty Modular Symetric Encryption (PMSE)   - Blocksnet.net    //
//      Author : Etienne Lemaire								   //
//      Last revision : 10/2023               					   //
// 		Modified version  the 1st version of PMSE 			// 
//		Published here: https://doi.org/10.48550/arXiv.1905.08150  //
/////////////////////////////////////////////////////////////////////////////

// List of Parameters:
// msg_tmp : string to be encoded/decoded
// mdp1 : password1
// mdp2 : password2
// iv : string(6 chars) for vector of initial values (6 values at least)
// modul_algo_param : char (8bit) for parameter to modulate encryption algo
// salt : string of pseudo random chars

/* PMSE encryption function : Base 16 encoding version */
function PMSE_enc_hex(msg_tmp, mdp1, mdp2, iv , salt, modul_algo_param)    {
	var i=0, j=0;
	var permute = (modul_algo_param.charCodeAt(0))& 0x03;
	var pol_order = ((modul_algo_param.charCodeAt(0))& 0x0C)>>2;
	var div_Yn_1 = ((modul_algo_param.charCodeAt(0))& 0x30)>>4;
	var b_cst = 1 + ((modul_algo_param.charCodeAt(0))& 0xC0)>>6;
	var cyph_srt = "*enc_=" + salt;
	var lm1 = mdp1.length;
	var lm2 = mdp2.length;
	var size_m = msg_tmp.length;
	var x0=iv.charCodeAt(0), x1=iv.charCodeAt(1), x2=iv.charCodeAt(2), x3=iv.charCodeAt(3), xt=iv.charCodeAt(4), ck_sum=[0,0,0,0], tmp_sum=0, Yn=iv.charCodeAt(5);
	
	for (i=0; i < size_m ; i++){ // Pseudo random chain generation (as long as msg) calculated from password 1 & 2 
		
		/////////////////////////////////////////
		// Bloc 1: Pseudo random byte generation
		//////////////////////////////////////////
		if ((pol_order%2)==0)                     
            Yn = x2*i*i + b_cst*x1*i + Yn>>div_Yn_1; // polynomial order 2 
		if ((pol_order%2)==1)				          
            Yn = x2*i + b_cst*x1 + Yn>>div_Yn_1; // polynomial order 1

          xa = (Yn & 0xFF000000)>>24 ;
          xb = (Yn & 0xFF0000)>>16 ;
          xc = (Yn & 0xFF00)>>8 ;
          xd = Yn & 0xFF;
          x0 = (xa^xb^xc^xd); //~=CRC8 of Yn
		
		
		x1 =  mdp1.charCodeAt(i%lm1); // 1 char from password1
		x2 =  mdp2.charCodeAt((x0+i)%lm2); // 1 char from password2
		x3 = ((Yn>>3) + (xt<<1))&0xFF; // x3 depends on Yn and from previous tmp_sum		
		xt = (x0^x1^x2^x3)&0xFF;  // pseudo-random key for xor encryption, depends on x0, x1, x2, x3
		
        if (xt==0){
			x0=i%iv.charCodeAt(0); x1=i%iv.charCodeAt(1); x2=i%iv.charCodeAt(2); x3=i%iv.charCodeAt(3); xt=i%iv.charCodeAt(4); Yn = i%iv.charCodeAt(5);
		}
		
		/////////////////////////////////////
		// BLOC2: Data byte deconstruction
		////////////////////////////////////
		msg_ = msg_tmp.charCodeAt(i);
		
		// bit switching 
		if (permute == 0)
			// split and exchange 4MSB and 4LSB  of msg
			msg_ = ((msg_ & 0xF0)>>4) + ((msg_ & 0x0F)<<4);
		if (permute == 1)
			// switch 2LSB and 2 LSB and 2 MSB and 2 MSB of msg
			msg_ = ((msg_ & 0xCC)>>2) + ((msg_ & 0x33)<<2) ;
		if (permute == 2)
			// switch only 2LSB with  2MSB  of msg
			msg_ = ((msg_ & 0xC0)>>6) + ((msg_ & 0x03)<<6)  + ((msg_ & 0x3C));
		if (permute == 3)
			// switch only medium bits of msg
			msg_ = ((msg_ & 0x30)>>2) + ((msg_ & 0x0C)<<2)  + ((msg_ & 0xC3));
		
        // partial bitwise not
        if (x0&0x03==0)
            msg_ = msg_^0xC0;
        if (x0&0x03==1)
            msg_ = msg_^0x30;
        if (x0&0x03==2)
            msg_ = msg_^0x0C;
        if (x0&0x03==3)
            msg_ = msg_^0x03;
		
		//////////////////////////
		// BLOC3: XOR encryption
		///////////////////////////
		crypt = (msg_ ^ xt )&0xFF; /// XOR (PRNG byte)^(deconstructed data byte) <=> encryption 
		
		// Formatting
		tmp = crypt.toString(16); // convert indice into hex chars
		if (crypt < 0x10){
			tmp = "0"+tmp;		}
		cyph_srt = cyph_srt.concat(tmp); // add char to string
		
		pol_order=x3; //update polynomial order
		
		// Checksum  ///////////
		k = i%4;
		
		ck_sum[k] = (((tmp_sum*tmp_sum)>>(msg_&0x07)) + (ck_sum[k]^(msg_)))&0xFFFFFFFF;
		ck_sum[0] = (ck_sum[0]^((msg_&0x81)<<((i)%24)))&0xFFFFFFFF;
		ck_sum[1] = (ck_sum[1]^((msg_&0x42)<<((msg_)%24)))&0xFFFFFFFF;
		ck_sum[2] = (ck_sum[2]^((msg_&0x24)<<((i+msg_)%24)))&0xFFFFFFFF;
		ck_sum[3] = (ck_sum[3]^((msg_&0x18)<<((msg_&0x1F)%24)))&0xFFFFFFFF;
		tmp_sum = ck_sum[0] + ck_sum[1] + ck_sum[2]+ ck_sum[3];
	}
	// print checksum to page in hexadecimal format
	document.getElementById("p_checksum").value = "Hx" + ck_sum[0].toString(16)+ ck_sum[1].toString(16)+ ck_sum[2].toString(16)+ ck_sum[3].toString(16);	
	
	
return cyph_srt;

}


/* PMSE decryption function : Base 16 encoding version */
function PMSE_dec_hex(msg_tmp, mdp1, mdp2, iv , salt, modul_algo_param)    {
	var i=0, j=0;
	var permute = (modul_algo_param.charCodeAt(0))& 0x03; 
	var pol_order = ((modul_algo_param.charCodeAt(0))& 0x0C)>>2;
	var div_Yn_1 = ((modul_algo_param.charCodeAt(0))& 0x30)>>4;
	var b_cst = 1 + ((modul_algo_param.charCodeAt(0))& 0xC0)>>6;
	
	var cyph_srt = "";
	// encryption header removal
	var n_start = msg_tmp.indexOf("*enc_=") + 6 + salt.length;
	msg_tmp = msg_tmp.slice(n_start, msg_tmp.length);
	
	var lm1 = mdp1.length;
	var lm2 = mdp2.length;
	var x0=iv.charCodeAt(0), x1=iv.charCodeAt(1), x2=iv.charCodeAt(2), x3=iv.charCodeAt(3), xt=iv.charCodeAt(4), ck_sum=[0,0,0,0], tmp_sum=0, Yn=iv.charCodeAt(5);
	
	for (i=0; i < (msg_tmp.length >> 1); i++){ // Pseudo random chain generation (as long as msg) calculated from password 1 & 2 
		
		
		/////////////////////////////////////////
		// Bloc 1: Pseudo random byte generation
		//////////////////////////////////////////
		
		if ((pol_order%2)==0)                     
            Yn = x2*i*i + b_cst*x1*i + Yn>>div_Yn_1; // polynomial order 2 
		if ((pol_order%2)==1)				         
            Yn = x2*i + b_cst*x1 + Yn>>div_Yn_1; // polynomial order 1 

          xa = (Yn & 0xFF000000)>>24 ;
          xb = (Yn & 0xFF0000)>>16 ;
          xc = (Yn & 0xFF00)>>8 ;
          xd = Yn & 0xFF;
          x0 = (xa^xb^xc^xd);
		
		
		x1 =  mdp1.charCodeAt(i%lm1); // simple itterative selection of char of password1
		x2 =  mdp2.charCodeAt((x0+i)%lm2); // // char selection from pseudo random key x0
		x3 = ((Yn>>3) + (xt<<1))&0xFF; // x3 depends on Yn and from previous tmp_sum		
		xt = (x0^x1^x2^x3)&0xFF;  // pseudo-random key for xor encryption, depends on x0, x1, x2, x3
        
		if (xt==0){
			x0=i%iv.charCodeAt(0); x1=i%iv.charCodeAt(1); x2=i%iv.charCodeAt(2); x3=i%iv.charCodeAt(3); xt=i%iv.charCodeAt(4); Yn = i%iv.charCodeAt(5);
		}
		
		////////////////////////////////
		//// BLOC2: XOR decryption ////
		/////////////////////////////////
		x_tmp = parseInt(msg_tmp.slice(j,j+2), 16);
		crypt = (x_tmp ^ xt )&0xFF ; //  values into [0-255] 
		
        
		/////////////////////////////////////
		// BLOC3: Data byte reconstruction
		////////////////////////////////////
		
        // partial bitwise not
        msg_ = crypt;
        if (x0&0x03==0)
            msg_ = msg_^0xC0;
        if (x0&0x03==1)
            msg_ = msg_^0x30;
        if (x0&0x03==2)
            msg_ = msg_^0x0C;
        if (x0&0x03==3)
            msg_ = msg_^0x03;

		// bit switching 
		if (permute == 0)
			// split and exchange 4MSB and 4LSB  of msg
			msg_ = ((msg_ & 0xF0)>>4) + ((msg_ & 0x0F)<<4);
		if (permute == 1)
			// switch 2LSB and 2 LSB and 2 MSB and 2 MSB of msg
			msg_ = ((msg_ & 0xCC)>>2) + ((msg_ & 0x33)<<2) ;
		if (permute == 2)
			// switch only 2LSB with  2MSB  of msg
			msg_ = ((msg_ & 0xC0)>>6) + ((msg_ & 0x03)<<6)  + ((msg_ & 0x3C));
		if (permute == 3)
			// switch only medium bits of msg
			msg_ = ((msg_ & 0x30)>>2) + ((msg_ & 0x0C)<<2)  + ((msg_ & 0xC3));

		crypt = msg_;
		
		tmp = String.fromCharCode(crypt); // convert indice into char
		cyph_srt = cyph_srt.concat(tmp); // add char to string
		
		j=j+2;
		pol_order=x3; //update polynomial order
		
		// Checksum /////////////////////////
		k = i%4;
		msg_ = crypt;
		ck_sum[k] = (((tmp_sum*tmp_sum)>>(msg_&0x07)) + (ck_sum[k]^(msg_)))&0xFFFFFFFF;
		ck_sum[0] = (ck_sum[0]^((msg_&0x81)<<((i)%24)))&0xFFFFFFFF;
		ck_sum[1] = (ck_sum[1]^((msg_&0x42)<<((msg_)%24)))&0xFFFFFFFF;
		ck_sum[2] = (ck_sum[2]^((msg_&0x24)<<((i+msg_)%24)))&0xFFFFFFFF;
		ck_sum[3] = (ck_sum[3]^((msg_&0x18)<<((msg_&0x1F)%24)))&0xFFFFFFFF;
		tmp_sum = ck_sum[0] + ck_sum[1] + ck_sum[2]+ ck_sum[3];
				
		
	}
	// print checksum to page in hexadecimal format
	document.getElementById("p_checksum").value = "Hx" + ck_sum[0].toString(16)+ ck_sum[1].toString(16)+ ck_sum[2].toString(16)+ ck_sum[3].toString(16);	
	
	
return cyph_srt;


}
