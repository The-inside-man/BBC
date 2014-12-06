//////////////////////////////////////////////////////////
//	Name:			Jacob Brown							//
//	Title:			BBC_CRYPTO - Brown Block Cipher		//
//	Updated:		23 November 2014					//
//////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////
//															//
//	Description:	A cryptographic algorithm developed to	//
//					learn more about what goes into the 	//
//					making of such algorithms. Algorithm 	//
//					consists of 256-bit keys and 1024-bit	//
//					block sizes. Has been tested on perso-	//
//					nal computers for brute force attacks.	//
//					Results were unsuccessful. Use for le-	//
//					arning purposes, or implementations of	//
//					your own. Use at your own risk. Not r-	//
//					esponsible for any type of information	//	
//					leakage of anykind associated with us-	//
//					ing this cryptographic algorithm or c-	//	
//					ode.									//
//															//
//					Key Size 	- 256 bits					//
//					block Size	- 1024 bits					//
//															//
//															//
//	Note: 	encrypt() and decrypt() are used by 			//
//			encrypt_blocks() and decrypt_blocks().			//
//															//
//////////////////////////////////////////////////////////////
#include "cipher.h"

using namespace std;

/* 	Blocks to be chained together by taking the
	encrypted block of the previous block and 
	using that as the key matrix for the next
	block */
string encrypt_blocks(string input, string key){
	int block_ptr = 0;
	if(input.length() < 128){
		return encrypt(input, key);
	}else{
		string rtn = "";
		while(1){
			if((input.length() - block_ptr) < 128){ 
				string tmp = input.substr(block_ptr, (input.length() - block_ptr));
				rtn  = rtn + encrypt(tmp,key);
				return rtn;
			} else{
				string tmp = input.substr(block_ptr,128);
				rtn = rtn + encrypt(tmp, key);
			}
			block_ptr = block_ptr + 128;
		}
	}
}

/* 	This function takes in some cipher text bit
	string and out puts the corresponding plain
	text bit string */
string decrypt_blocks(string input, string key){
	int block_ptr = 0;
	string rtn = "";
	while(block_ptr < input.length()){
		string tmp1 = input.substr(block_ptr, 1024);
		string tmp = decrypt(tmp1, key);
		int len = tmp.length();
		int i,ctr = 0;
		for(i = len - 1; i > 0; i --){
			if(tmp[i] == ' '){
				tmp.erase(i);
			}else{
				i = 0;
			}
		}
		rtn += tmp;
		block_ptr += 1024;
	}
	
 	return rtn;
}

/*	Function to convert ascii values
	to binary string */
string A_to_B(int n){
	int result = 0, m = 1, remainder;
    while (n > 0) {
        remainder = n % 2;
        result = result + (m * remainder);
        n = n / 2;
        m = m * 10;
    }
	string num = to_string(result);
	while (num.length() < 8){
		num.insert(num.begin(),'0');
	}
	
	return num;
}

/* 	Takes an 8 bit input string 
	and returns the numerical 
	ascii value */
int B_to_A(string bits){
	int i = 0;
	int ctr = 7;
	int accum = 0;
	if(bits.length() != 8) exit(1); // Confirms 8 bit length of bitstring
	for(i = 0; i < 8; i ++){
		string str;
		str.push_back(bits[i]);
		int tmp = stoi(str);
		if(tmp == 0){
			ctr--;
		} else if(tmp == 1){
			accum += pow(2,ctr);
			ctr--;
		}
	}
	return accum;
}

/* 	Encryption Algorithm E(P) return C 
	Here we take some plaintext in string
	form and convert it to bits. Then the
	bits are loaded into a matrix. The same
	is done with the provided key string. 
	the key matrix created is then xor'd 
	with the bits of the plaintext matrix.
	The next step is a shift of each row
	by n positions, starting from 1 to 32.
	after the shift we reverse the key and
	repeat the first couple steps. Last 
	the cipher text bit string is returned. */
string encrypt(string plaintext, string key){
	
	/* Variables declared here*/
	int lengthl 		= plaintext.length();
	int key_length 		= key.length();
	int i 				= 0;
	int j 				= 0;
	string line 		= "";
	string ciphertext 	= "";
	int length 			= 32;
	
	string matrix[32][32]; // Matrix to store data
	string kmatrix[32][32];// Key matrix



	int len = (plaintext.length() * 8);
	
	// add padding to plaintext if needed
	if(len < 1024){
		while(plaintext.length() < 128){
			plaintext.insert(plaintext.end(), ' ');
		}
	}
		
	// convert plaintext to 1024 bit string
	int ctr = 0,eight = 0;
	string block = "";
	for(;ctr < 128; ctr++){
		string tmp = A_to_B(static_cast<int>(plaintext[ctr]));
		block.insert(eight,tmp);
		eight += 8;
	}

	/* Here we load the bits into the 32 x 32 matrix */	
	int m = 0, n = 0, ct = 0;
	for(m = 0; m < 32; m++){
		for(n = 0; n < 32; n++){
			matrix[m][n] = block[ct];
			ct ++;
		}
	}
	
	// key goes from ascii to binary here
	string keyStr = "";
	eight = 0;
	for(i = 0; i < 32; i++){
		string tmp = A_to_B(static_cast<int>(key[i]));
		keyStr.insert(eight,tmp);
		eight += 8;
	} 
	
	// then the key is loaded into a matrix
	ctr = 0;
		for(i = 0; i < 32; i ++){
			for(j = 0; j < 32; j ++){
				if(ctr > 255){
					ctr = 0;
				}
				kmatrix[i][j] = keyStr[ctr];
				ctr ++;
			}
		}		
	
	for(i = 0; i < 32; i ++){
		for(j = 0; j < 32; j ++){
			matrix[i][j] = x_or(matrix[i][j],kmatrix[i][j]);
		}
	}
	
	/* Shift the matrix by n times starting at 1 */
	n = 1;
	for(i = 0; i < 32; i ++){
		for(j = 0; j < n; j++){
			rotate(matrix,i);
		}
		n++;
	}
	
	reverse(begin(key),end(key));
	
	keyStr = "";
	eight = 0;
	for(i = 0; i < 32; i++){
		string tmp = A_to_B(static_cast<int>(key[i]));
		keyStr.insert(eight,tmp);
		eight += 8;
	} 
	
	ctr = 0;
		for(i = 0; i < 32; i ++){
			for(j = 0; j < 32; j ++){
				if(ctr > 255){
					ctr = 0;
				}
				kmatrix[i][j] = keyStr[ctr];
				ctr ++;
			}
		}
				
	for(i = 0; i < 32; i ++){
		for(j = 0; j < 32; j ++){
			matrix[i][j] = x_or(matrix[i][j],kmatrix[i][j]);
		}
	}
	
	string bit_string = "";
	for(i = 0; i < 32; i++){
		for(j = 0; j < 32; j++){
			bit_string += matrix[i][j];
		}
	}
	
	return bit_string;
}

/* 	Function used to rotate a row
	of a matrix 1 time to the left */
void rotate(string array[][32], int j){
	int i = 0;
	string tmp = array[j][0];
	for (i = 0; i < 32; i++){
		if( i + 1 == 32 ){
			array[j][i] = tmp;
		}else {
			array[j][i] = array[j][i+1];
		}
	}
}

/*	A simple x or function */
string x_or(string x, string y){
	if(x == "0" && y == "0"){
		return "0";
	}else if(x == "1" && y == "0"){
		return "1";
	}else if(x == "0" && y == "1"){
		return "1";
	}else if(x == "1" && y == "1"){
		return "0";
	}else {
		return "0";
	}
}

/* 	Decryption Algorithm: The opposite of
	same steps of the encryption algorithm,
	except takes a bit-string for cipher-
	text and returns the decrypted bit-
	string */
string decrypt(string ciphertext, string key){
/* Variables declared here*/
	int lengthl 		= ciphertext.length();
	int key_length 		= key.length();
	int i 				= 0;
	int j 				= 0;
	string line 		= "";
	int length 			= 32;
	
	string matrix[32][32]; // Matrix to store data
	string kmatrix[32][32];// Key matrix
	
	// convert plaintext to 1024 bit string
	int ctr = 0;
	int eight = 0;
	
	/* Here we load the bits into the 32 x 32 matrix */	
	int m = 0, n = 0, ct = 0;
	for(m = 0; m < 32; m++){
		for(n = 0; n < 32; n++){
			matrix[m][n] = ciphertext[ct];
			ct ++;
		}
	}
	
	reverse(begin(key),end(key)); // we reverse the key
	
	
	string keyStr = "";
	eight = 0;
	for(i = 0; i < 32; i++){
		string tmp = A_to_B(static_cast<int>(key[i])); // we load the key into the a string of bits
		keyStr.insert(eight,tmp);
		eight += 8;
	} 

	
	ctr = 0;
		for(i = 0; i < 32; i ++){		//We input the bits into a matrix made up of the key
			for(j = 0; j < 32; j ++){
				if(ctr > 255){
					ctr = 0;
				}
				kmatrix[i][j] = keyStr[ctr];
				ctr ++;
			}
		}
   
   	/*	The key matrix is xor'd with the message matrix */
	for(i = 0; i < 32; i ++){
		for(j = 0; j < 32; j ++){
			matrix[i][j] = x_or(matrix[i][j],kmatrix[i][j]);
		}
	}
	
	
	//reverse the key again
	reverse(begin(key),end(key));
	keyStr = "";
	eight = 0;
	for(i = 0; i < 32; i++){
		string tmp = A_to_B(static_cast<int>(key[i])); // we load the key into the a string of bits
		keyStr.insert(eight,tmp);
		eight += 8;
	} 
	
	ctr = 0;
		for(i = 0; i < 32; i ++){		//We input the bits into a matrix made up of the key
			for(j = 0; j < 32; j ++){
				if(ctr > 255){
					ctr = 0;
				}
				kmatrix[i][j] = keyStr[ctr];
				ctr ++;
			}
		}
	
	/* We rotate the matrix back to original positions */	
	n = 32;
	for(i = 31; i >= 0; i --){
		for(j = 0; j < n ; j++){
			rotate(matrix,i);
		}
		n++;
	}
	
	/* Final xor step */
	for(i = 0; i < 32; i ++){
		for(j = 0; j < 32; j ++){
			matrix[i][j] = x_or(matrix[i][j],kmatrix[i][j]);
		}
	}
	
	/* load the matrix into a bit string to be returned */
	string bit_string = "";
	for(i = 0; i < 32; i ++){
		for(j = 0; j < 32; j ++){
			bit_string += matrix[i][j];
		}
	}
	
	return bit_string;
}

/* 	Function used to take some bit string 
	and convert to a string of characters */
void show_text(string bit_string){
	int i,y = 0;
	string temp = "";
	string chars = "";
	for(i = 0; i < bit_string.length(); i++){
		temp += bit_string[i];
		if(y == 7){
			int number = B_to_A(temp); 
			char test = static_cast<char>(number);
			chars += test;
			y = 0;
			temp = "";
		}else{
			y++;
		}		
	}
	cout << chars << endl;
}




