/**
 *  
 *  Certificate Operations - The following program deals with the process
 *  of creation of a java program which deals with purpose of verifying Raghu's
 *  Certificate which comes in three forms. One is a public certificate belonging 
 *  someone called “Raghu” (Raghupub.cer). Another is a file containing the 
 *  private key corresponding to it (Raghupri.pfx) and the password on pfx file 
 *  is "raghu", and the third is the CA public certificate (Trustcenter.cer). 
 *  
 *  @Author Balaji Chandrasekaran
 *  @version 1.4
 *  @since 04/03/2017
 *
 */

// This import corresponds to the purpose of reading the file.
import java.io.FileInputStream;

/* Import corresponding to the ones provided in description for certificate verification
 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html"
 */
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
// import for enumeration interface.
import java.util.*;
// import for xml editor.
import javax.xml.bind.DatatypeConverter;
//import for RSA cipher objects.
import javax.crypto.Cipher;
// import for base64 handling.
import org.apache.commons.codec.binary.Base64;
// import for exceptions.
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

/**
 * The class below contains mechanism to verify the certificates and display the result
 * of all the operations requested by professor. The operations are:
 * 1) Verify Raghu’s certificate.
 * 2) Print the certificate.
 * 3) Print Raghu’s public and private key
 * 4) Print the public Key of Certification Authority.
 * 5) Print the signature on Raghu’s certificate
 * 6) Encrypt and Decrypt the following string using RSA.
 * 		“Our names are  << names>>. We are enrolled in CSE 539.”
 * 
 * @author Balaji Chandrasekaran.
 *
 */

/* 
 * References: 
 * http://stackoverflow.com/questions/13500368/encrypt-and-decrypt-large-string-in-java-using-rsa 
 * https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
 * http://stackoverflow.com/questions/21166352/printing-an-rsa-private-key-doesnt-actually-return-it
 * http://stackoverflow.com/questions/18375813/display-alias-password-from-keystore-certificate
 * http://www.java2s.com/Tutorial/Java/0490__Security/DisplaypropertiesofX509Certificate.htm
 * http://stackoverflow.com/questions/15818782/how-to-verify-a-certificate-using-cer-file-in-java
 * */
public class CertificateVerify 
{
	/**	 
	 * 
	 * The function below is an encrypt function that is used for the
	 * purpose of encrypting the given text with the public-key provided.
	 * For the same purpose we use RSA to encrypt.
	 * 
	 * @param  text       Which is the text that is to be encrypted.
	 * @param  publicKey  Which is the key that is used for encrypting the text.
	 * @return String     Which is the encrypted string that is output of the function.
	 * 
	 */
	public static String encrypt(String text, PublicKey publicKey) 
	{
		Cipher cipheringObj;
		StringBuilder strBuilder = new StringBuilder();
		byte[] cipherBytes = null;
		//Base64 retObj = new Base64();
		try
		{
			cipheringObj = Cipher.getInstance("RSA");
			cipheringObj.init(Cipher.ENCRYPT_MODE, publicKey);
			cipherBytes = (cipheringObj.doFinal(text.getBytes("UTF-8")));
			strBuilder.append(Base64.encodeBase64String(cipherBytes));
		}
		catch(IOException e)
		{
			System.out.println("There is a following IOException Occuring : " + e);
		}
		catch(GeneralSecurityException e)
		{
			System.out.println("There is a following GeneralSecurityException Occuring : " + e);
		}
		return strBuilder.toString();
	}

	/**	 
	 * 
	 * The function below is an decrypt function that is used for the
	 * purpose of decrypting the given text with the private-key provided.
	 * For the same purpose we use RSA to decrypt.
	 * 
	 * @param  text       Which is the text that is to be decrypted.
	 * @param  privateKey  Which is the key that is used for decrypting the text.
	 * @return String     Which is the encrypted string that is output of the function.
	 * 
	 */
	public static String decrypt(String text, PrivateKey privateKey)
	{
		Cipher cipheringObj;
		String retString = "";
		try
	    {
	    	cipheringObj = Cipher.getInstance("RSA");
	    	cipheringObj.init(Cipher.DECRYPT_MODE, privateKey);
	    	retString = new String(cipheringObj.doFinal(Base64.decodeBase64(text)), "UTF-8");
	    }
		catch(IOException e)
		{
			System.out.println("There is a following IOException Occuring : " + e);
		}
		catch(GeneralSecurityException e)
		{
			System.out.println("There is a following GeneralSecurityException Occuring : " + e);
		}
		return retString;
	}
		
	/**	 
	 * 
	 * The function below is the main function that is used for the
	 * purpose of verifying all the three certificates of raghu which 
	 * are public key certificate, CA provided certificate and private key 
	 * certificate.
	 * 
	 * @param  args[]	Which is usual main() argument.
	 * @return void     There is no return type as the output is comprised of prints.
	 * @throws KeyStoreException 
	 * 
	 */	
	public static void main(String args[]) throws KeyStoreException
	{
		/*
		 * Problem Of Verifying Raghu's Certificate.
		 */
		String publicCACertificate	= "";
	    String publicCertificate	= "";
	    String pfxCertificate		= "";
	    String aliasStr				= "";
	    String password             = "";
	    PrivateKey privateKey;
	    PublicKey publicKey;
	    RSAPrivateKey privateRSAKey;
	    KeyStore storeKey;
	    
	    FileInputStream publicCertificateFile;
	    FileInputStream publicCACertificateFile;
	    FileInputStream pfxCertificateFile;
	    X509Certificate taPublicCertificate;
	    X509Certificate caCertificate;
	    PublicKey caPublicKey;
	    CertificateFactory certificateObj;
	    byte[] signature;
        String inputText   = "My name is Balaji Chandrasekaran. I am enrolled in.";
		Key key;
        try
		{
			publicCACertificate = "Trustcenter.cer";
		    publicCertificate	= "Raghupub.cer";
		    pfxCertificate      = "Raghupri.pfx";
		    password            = "raghu";
		
		    certificateObj 	  = CertificateFactory.getInstance("X509");
		    
		    publicCertificateFile	= new FileInputStream(publicCertificate);
		    publicCACertificateFile = new FileInputStream(publicCACertificate);
		    pfxCertificateFile		= new FileInputStream(pfxCertificate);

		    taPublicCertificate	  = (X509Certificate) certificateObj.generateCertificate(publicCertificateFile);		    
		    caCertificate    	  = (X509Certificate) certificateObj.generateCertificate(publicCACertificateFile);
		    caPublicKey 		  = caCertificate.getPublicKey();

		    /*
		     * Validating the raghu's certificate using the public key. 
		     * If verification fails throws exception.
		     */
		    taPublicCertificate.verify(caPublicKey);
			System.out.println("\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		    System.out.println("!!!!!!!!!!!!!!!!!!!!!!!! THE CERTIFICATE IS VALID !!!!!!!!!!!!!!!!!!!!!!!!");
			System.out.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
		
			
		    storeKey	=	KeyStore.getInstance("pkcs12", "SunJSSE");
		    storeKey.load(pfxCertificateFile, password.toCharArray());
		    Enumeration enu = storeKey.aliases();
		 
		    
		    if(enu.hasMoreElements()) 
		    {
		        aliasStr = (String)enu.nextElement();
		        X509Certificate certificate = (X509Certificate)storeKey.getCertificate(aliasStr);
		        key                     	= storeKey.getKey(aliasStr, password.toCharArray());
		
		        /*
		         * PROBLEM 1 : Printing raghu's certificate. 
		         */
		        System.out.println("PROBLEM 1:");
		        System.out.println("\n\t    !!!!!!!!!!!!! RAGHU'S CERTIFICATE !!!!!!!!!!!!!");
		        System.out.println(certificate.toString() + "\n");
		        
		        /*
		         * PROBLEM 2 : Printing raghu's PUBLIC and PRIVATE key.
		         */
		        privateRSAKey	= (RSAPrivateKey) key;
		        privateKey 		= (PrivateKey)key;
		        publicKey  		= certificate.getPublicKey();
		 
		        System.out.println("PROBLEM 2:");
		        System.out.println("\n\t\t\t!!!!!!!!!!!!! RAGHU'S PRIVATE KEY !!!!!!!!!!!!!" + "\n\n\n  " +key);
		        System.out.println("  modulus  : " + privateRSAKey.getModulus());
		        System.out.println("  private exponent : " + privateRSAKey.getPrivateExponent());
		        System.out.println("\n\t\t\t!!!!!!!!!!!!! RAGHU'S PUBLIC KEY !!!!!!!!!!!!!" +"\n\n\n  " + publicKey);
		        
		        /*
		         * PROBLEM 3 : Print the signature on Raghu’s certificate.
		         */
		        System.out.println("\n\nPROBLEM 3:");
		        byte[] sign = certificate.getSignature();
		        System.out.println("\n\t\t\t!!!!!!!!!!!!! SIGNATURE - RAGHU'S CERTIFICATE !!!!!!!!!!!!!"+"\n\n\n   " + new BigInteger(sign).toString(16));
		        
		        
		        /*
		         * PROBLEM 4 : Encrypting and Decrypting the following string using RSA
		         * “My name is  << name>>. I am enrolled in.”.
		         */	
		        System.out.println("\n\nPROBLEM 4:");
		        System.out.println("\n\t\t\t!!!!!!!!!!!!! ENCRYPTED TEXT !!!!!!!!!!!!!" + "\n\n\n   " + encrypt(inputText,publicKey));
		        System.out.println("\n\t\t\t!!!!!!!!!!!!! DECRYPTED TEXT !!!!!!!!!!!!!" + "\n\n\n   \"" + decrypt(encrypt(inputText,publicKey),privateKey) + "\"");
		    }
		    else
		    {
		    	System.out.println("Fatal Error there is nothing in keystore");
		    }

	        /*
	         * PROBLEM 5 : Printing the public Key of Certification Authority.
	         */	
	        System.out.println("\n\nPROBLEM 5:");
		    System.out.println("\n\t\t\t!!!!!!!!!!!!! PUBLIC KEY OF CERTIFICATION AUTHORITY !!!!!!!!!!!!!\n\n\n  " + caPublicKey.toString());

		}
		catch(Exception e)
		{
			System.out.println("There is a Exception : " + e);
		}
	}
}