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

#include <iostream>			// Used for in out stream
#include <iomanip>			// Used for in out manipulation
#include <fstream>			// Used for files in and out
#include <string.h>			// Used for string manipulation
#include <stdlib.h>			// Used for standard Library
#include <math.h>			// Used for calculating the power of
#include <algorithm>		// Used for reverse of Key

/* Functions Below */
int B_to_A(std::string);								// Converts from Binary to ascii
void show_text(std::string);							// Displays the text equivalent of bit-string
void rotate(std::string[][32], int);					// Shifts elements of matrix row to the left by 1
std::string A_to_B(int);								// Converts from ascii to binary
std::string x_or(std::string, std::string);				// Xors two bits in string form
std::string encrypt(std::string, std::string);			// Takes plaintext P and converts it to ciphertext bit-string
std::string decrypt(std::string, std::string);			// Takes some ciphertext bit-string and converts it to some plaintext bit-string
std::string encrypt_blocks(std::string, std::string);	// Encrypts n number of blocks using encrypt()
std::string decrypt_blocks(std::string, std::string);	// Decrypts n number of blocks using decrypt()
