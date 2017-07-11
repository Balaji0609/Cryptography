#include "RSA.h"
#include "BigInt.h"
#include <cmath>
#include<iostream>
#include<cstdlib>

#define RAND_LIMIT32 0x7FFFFFFF
#define RAND_LIMIT16 0x7FFF
using namespace RSAUtil;
/*

Balaji Chandrasekaran - 1208948451

*/
int main(int argc, char*argv[]){      
 
        
        RSA aliceRSA, bobRSA;

	BigInt alicePublicKey, bobPublicKey;
        BigInt aliceModulus, bobModulus;
 // Alice obtains the public key and Modulus N of the person (Bob) who is to sign the message
        aliceRSA.setPublicKey(bobRSA.getPublicKey());
        aliceRSA.setN(bobRSA.getModulus());
        
        alicePublicKey = aliceRSA.getPublicKey();
        aliceModulus = aliceRSA.getModulus(); 
         std::cout<<"Alice obtains the public key and Modulus N of the person (Bob) who is to sign the message"<<"\n";
        std::cout<<"Public key of the signer: "<<alicePublicKey.toHexString()<<"\n";
	std::cout<<"Modulus of the signer : "<<aliceModulus.toHexString()<<"\n";
        std::cout<<"-----------------------------------------------------------\n";

//Obtain a random number and its inverse with respect to the Modulus [Not phi] of Bob
        BigInt randomno, inverse;
         
        randomno = int(((double)rand()/RAND_MAX) * RAND_LIMIT16);
        inverse = modInverse(randomno, bobRSA.getModulus());
         std::cout<<"Obtain a random number and its inverse with respect to the Modulus [Not phi] of Bob"<<"\n";
        std::cout<<"Random Number: "<<randomno.toHexString()<<"\n";
	std::cout<<"Inverse : "<<inverse.toHexString()<<"\n";
         std::cout<<"-----------------------------------------------------------\n";
//Alice obtains/generates a message to be signed.
        BigInt message;

        message = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT32);
       std::cout<<"Alice obtains/generates a message to be signed."<<"\n";
        std::cout<<"Message to be signed: "<<message.toHexString()<<"\n";
         std::cout<<"-----------------------------------------------------------\n";

//Alice encrypts the random number with the public key. 
         BigInt encrypt_randomno;
         encrypt_randomno = aliceRSA.encrypt(randomno);
          std::cout<<"Alice encrypts the random number with the public key. "<<"\n";
          std::cout<<"Encrypted random number: "<<encrypt_randomno.toHexString()<<"\n";
          std::cout<<"-----------------------------------------------------------\n";
// Alice multiplies this value by the message
        BigInt modified_message;
        modified_message = encrypt_randomno * message;
        std::cout<<""<<"\n";
        std::cout<<"Message * (encrypted random number) : "<<modified_message.toHexString()<<"\n";
        std::cout<<"-----------------------------------------------------------\n";
// Alice then takes a modulus over N
        BigInt final_message;
        final_message = modified_message % (bobRSA.getModulus());
        std::cout<<"Alice then takes a modulus over N"<<"\n";
        std::cout<<"Message before sending to Bob : "<<final_message.toHexString()<<"\n";
         std::cout<<"-----------------------------------------------------------\n";
// Alice sends it to Bob
         std::cout<<"Alice sends it to Bob "<<"\n";
         
// Bob simply decrypts the received value with the private key
        BigInt deciphered; 
        deciphered = bobRSA.decrypt(final_message);
        
        std::cout<<"Bob simply decrypts the received value with the private key"<<"\n";
        std::cout<<"Bob decrypts the received value with the private key: "<<deciphered.toHexString()<<"\n";
         std::cout<<"-----------------------------------------------------------\n";
// Bob sends it back to Alice
       std::cout<<"Bob sends it back to Alice"<<"\n";
//Alice then multiplied the received value with the inverse and takes a modulus over N.
        BigInt signed_message = (deciphered * inverse) % (bobRSA.getModulus());
        std::cout<<"Alice then multiplied the received value with the inverse and takes a modulus over N."<<"\n";
        std::cout<<"Signed message : "<<signed_message.toHexString()<<"\n";
        std::cout<<"-----------------------------------------------------------\n"; 
//The value obtained above is the signed message. To obtain the original message from it, again encrypt it with Bob’s Public Key.  
        BigInt original_message = aliceRSA.encrypt(signed_message);
        std::cout<<"The value obtained above is the signed message. To obtain the original message from it, again encrypt it with Bob’s Public Key. "<<"\n";
        std::cout<<"Original message : "<<original_message.toHexString()<<"\n";
         std::cout<<"-----------------------------------------------------------\n";
        return 0;
}
