#include "cipher.h"
#include <stdio.h>
#include <iostream>
#include <string>
#include <fstream>


using namespace std;

int main(){
	ifstream afile;
	afile.open("encrypt.txt");
	string line;
	string encrypt_text = "";
	if (afile.is_open())
  	{
    	while(getline(afile,line) )
    	{
      		encrypt_text += line;
    	}
    	afile.close();
  	}
  	
	string test = "Now this is a story all about how my life got flipped turned upside down and id like to tak a minute to sit right here and tell you how i became a prince of a town called Belair";
	string key = "UHD9J9QHUDELNLG4AL98E47ZLZIUAQ64";	
	
	string ciphertext = encrypt_blocks(encrypt_text, key);
	string plaintext = decrypt_blocks(ciphertext, key);
	cout << "Cipher Text: \n";
	show_text(ciphertext);
	cout << endl << "Plain Text: \n"; 
	show_text(plaintext);
	
	return 0;
}