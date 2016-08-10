
```

php服务器，java服务器，android，ios开发兼容的3des加密解密，

php 

<?php
class DES3 {
	var $key = "my.oschina.net/penngo?#@";
	var $iv = "01234567";

	function encrypt($input){
		$size = mcrypt_get_block_size(MCRYPT_3DES,MCRYPT_MODE_CBC);
		$input = $this->pkcs5_pad($input, $size);
		$key = str_pad($this->key,24,'0');
		$td = mcrypt_module_open(MCRYPT_3DES, '', MCRYPT_MODE_CBC, '');
		if( $this->iv == '' )
		{
			$iv = @mcrypt_create_iv (mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
		}
		else
		{
			$iv = $this->iv;
		}
		@mcrypt_generic_init($td, $key, $iv);
		$data = mcrypt_generic($td, $input);
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);
		$data = base64_encode($data);
		return $data;
	}
	function decrypt($encrypted){
		$encrypted = base64_decode($encrypted);
		$key = str_pad($this->key,24,'0');
		$td = mcrypt_module_open(MCRYPT_3DES,'',MCRYPT_MODE_CBC,'');
		if( $this->iv == '' )
		{
			$iv = @mcrypt_create_iv (mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
		}
		else
		{
			$iv = $this->iv;
		}
		$ks = mcrypt_enc_get_key_size($td);
		@mcrypt_generic_init($td, $key, $iv);
		$decrypted = mdecrypt_generic($td, $encrypted);
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);
		$y=$this->pkcs5_unpad($decrypted);
		return $y;
	}
	function pkcs5_pad ($text, $blocksize) {
		$pad = $blocksize - (strlen($text) % $blocksize);
		return $text . str_repeat(chr($pad), $pad);
	}
	function pkcs5_unpad($text){
		$pad = ord($text{strlen($text)-1});
		if ($pad > strlen($text)) {
			return false;
		}
		if (strspn($text, chr($pad), strlen($text) - $pad) != $pad){
			return false;
		}
		return substr($text, 0, -1 * $pad);
	}
	function PaddingPKCS7($data) {
		$block_size = mcrypt_get_block_size(MCRYPT_3DES, MCRYPT_MODE_CBC);
		$padding_char = $block_size - (strlen($data) % $block_size);
		$data .= str_repeat(chr($padding_char),$padding_char);
		return $data;
	}
}

$des = new DES3();
echo $ret = $des->encrypt("来自http://my.oschina.net/penngo的博客") . "\n";
echo $des->decrypt($ret) . "\n";


java(android)

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;  

import javax.crypto.Cipher;  
import javax.crypto.SecretKeyFactory;  
import javax.crypto.spec.DESedeKeySpec;  
import javax.crypto.spec.IvParameterSpec;  
        
/** 
  * 3DES加密工具类 
  */ 
public class DES3 {  
     // 密钥  
     private final static String secretKey = "my.oschina.net/penngo?#@" ;   
     // 向量  
     private final static String iv = "01234567" ;  
     // 加解密统一使用的编码方式  
     private final static String encoding = "utf-8" ;  
        
     /** 
      * 3DES加密 
      *  
      * @param plainText 普通文本 
      * @return 
      * @throws Exception  
      */ 
     public static String encode(String plainText) throws Exception {  
         Key deskey = null ;  
         DESedeKeySpec spec = new DESedeKeySpec(secretKey.getBytes());  
         SecretKeyFactory keyfactory = SecretKeyFactory.getInstance( "desede" );  
         deskey = keyfactory.generateSecret(spec);  
        
         Cipher cipher = Cipher.getInstance( "desede/CBC/PKCS5Padding" );  
         IvParameterSpec ips = new IvParameterSpec(iv.getBytes());  
         cipher.init(Cipher.ENCRYPT_MODE, deskey, ips);  
         byte [] encryptData = cipher.doFinal(plainText.getBytes(encoding));  
         return Base64.encode(encryptData);  
     }  
        
     /** 
      * 3DES解密 
      *  
      * @param encryptText 加密文本 
      * @return 
      * @throws Exception 
      */ 
     public static String decode(String encryptText) throws Exception {  
         Key deskey = null ;  
         DESedeKeySpec spec = new DESedeKeySpec(secretKey.getBytes());   
         SecretKeyFactory keyfactory = SecretKeyFactory.getInstance( "desede" );  
         deskey = keyfactory.generateSecret(spec);  
         Cipher cipher = Cipher.getInstance( "desede/CBC/PKCS5Padding" );  
         IvParameterSpec ips = new IvParameterSpec(iv.getBytes());  
         cipher.init(Cipher.DECRYPT_MODE, deskey, ips);  
        
         byte [] decryptData = cipher.doFinal(Base64.decode(encryptText));  
        
         return new String(decryptData, encoding);  
     }  
     
 	public static String padding(String str) {
		byte[] oldByteArray;
		try {
			oldByteArray = str.getBytes("UTF8");
			int numberToPad = 8 - oldByteArray.length % 8;
			byte[] newByteArray = new byte[oldByteArray.length + numberToPad];
			System.arraycopy(oldByteArray, 0, newByteArray, 0,
					oldByteArray.length);
			for (int i = oldByteArray.length; i < newByteArray.length; ++i) {
				newByteArray[i] = 0;
			}
			return new String(newByteArray, "UTF8");
		} catch (UnsupportedEncodingException e) {
			System.out.println("Crypter.padding UnsupportedEncodingException");
		}
		return null;
	}
	
	/** 
	  * Base64编码工具类 
	  * 
	  */ 
	public static class Base64 {  
	     private static final char [] legalChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" .toCharArray();  
	        
	     public static String encode( byte [] data) {  
	         int start = 0 ;  
	         int len = data.length;  
	         StringBuffer buf = new StringBuffer(data.length * 3 / 2 );  
	        
	         int end = len - 3 ;  
	         int i = start;  
	         int n = 0 ;  
	        
	         while (i <= end) {  
	             int d = (((( int ) data[i]) & 0x0ff ) << 16 ) | (((( int ) data[i + 1 ]) & 0x0ff ) << 8 ) | ((( int ) data[i + 2 ]) & 0x0ff );  
	        
	             buf.append(legalChars[(d >> 18 ) & 63 ]);  
	             buf.append(legalChars[(d >> 12 ) & 63 ]);  
	             buf.append(legalChars[(d >> 6 ) & 63 ]);  
	             buf.append(legalChars[d & 63 ]);  
	        
	             i += 3 ;  
	        
	             if (n++ >= 14 ) {  
	                 n = 0 ;  
	                 buf.append( " " );  
	             }  
	         }  
	        
	         if (i == start + len - 2 ) {  
	             int d = (((( int ) data[i]) & 0x0ff ) << 16 ) | (((( int ) data[i + 1 ]) & 255 ) << 8 );  
	        
	             buf.append(legalChars[(d >> 18 ) & 63 ]);  
	             buf.append(legalChars[(d >> 12 ) & 63 ]);  
	             buf.append(legalChars[(d >> 6 ) & 63 ]);  
	             buf.append( "=" );  
	         } else if (i == start + len - 1 ) {  
	             int d = ((( int ) data[i]) & 0x0ff ) << 16 ;  
	        
	             buf.append(legalChars[(d >> 18 ) & 63 ]);  
	             buf.append(legalChars[(d >> 12 ) & 63 ]);  
	             buf.append( "==" );  
	         }  
	        
	         return buf.toString();  
	     }  
	        
	     private static int decode( char c) {  
	         if (c >= 'A' && c <= 'Z' )  
	             return (( int ) c) - 65 ;  
	         else if (c >= 'a' && c <= 'z' )  
	             return (( int ) c) - 97 + 26 ;  
	         else if (c >= '0' && c <= '9' )  
	             return (( int ) c) - 48 + 26 + 26 ;  
	         else 
	             switch (c) {  
	             case '+' :  
	                 return 62 ;  
	             case '/' :  
	                 return 63 ;  
	             case '=' :  
	                 return 0 ;  
	             default :  
	                 throw new RuntimeException( "unexpected code: " + c);  
	             }  
	     }  
	        
	     /** 
	      * Decodes the given Base64 encoded String to a new byte array. The byte array holding the decoded data is returned. 
	      */ 
	        
	     public static byte [] decode(String s) {  
	        
	         ByteArrayOutputStream bos = new ByteArrayOutputStream();  
	         try {  
	             decode(s, bos);  
	         } catch (IOException e) {  
	             throw new RuntimeException();  
	         }  
	         byte [] decodedBytes = bos.toByteArray();  
	         try {  
	             bos.close();  
	             bos = null ;  
	         } catch (IOException ex) {  
	             System.err.println( "Error while decoding BASE64: " + ex.toString());  
	         }  
	         return decodedBytes;  
	     }  
	        
	     private static void decode(String s, OutputStream os) throws IOException {  
	         int i = 0 ;  
	        
	         int len = s.length();  
	        
	         while ( true ) {  
	             while (i < len && s.charAt(i) <= ' ' )  
	                 i++;  
	        
	             if (i == len)  
	                 break ;  
	        
	             int tri = (decode(s.charAt(i)) << 18 ) + (decode(s.charAt(i + 1 )) << 12 ) + (decode(s.charAt(i + 2 )) << 6 ) + (decode(s.charAt(i + 3 )));  
	        
	             os.write((tri >> 16 ) & 255 );  
	             if (s.charAt(i + 2 ) == '=' )  
	                 break ;  
	             os.write((tri >> 8 ) & 255 );  
	             if (s.charAt(i + 3 ) == '=' )  
	                 break ;  
	             os.write(tri & 255 );  
	        
	             i += 4 ;  
	         }  
	     }  
	} 
     
     public static void main(String[] args) throws Exception{
    	 String plainText = "来自http://my.oschina.net/penngo的博客";
    	 String encryptText = DES3.encode(plainText);
    	 System.out.println(encryptText);
    	 System.out.println(DES3.decode(encryptText));

    	 
     }
}


Ojbective-C(ios)

//  
//  DES3Util.h  
//  
#import <Foundation/Foundation.h>  
@interface DES3Util : NSObject {  
}  
// 加密方法  
+ (NSString*)encrypt:(NSString*)plainText;  
// 解密方法  
+ (NSString*)decrypt:(NSString*)encryptText;  
@end 


//  
//  DES3Util.m  
//  
        
#import "DES3Util.h"  
#import <CommonCrypto/CommonCryptor.h>  
#import "GTMBase64.h"  
#define gkey            @"my.oschina.net/penngo?#@"  
#define gIv             @"01234567"  
        
@implementation DES3Util  
// 加密方法  
+ (NSString*)encrypt:(NSString*)plainText {  
     NSData* data = [plainText dataUsingEncoding:NSUTF8StringEncoding];  
     size_t plainTextBufferSize = [data length];  
     const void *vplainText = (const void *)[data bytes];  
            
     CCCryptorStatus ccStatus;  
     uint8_t *bufferPtr = NULL;  
     size_t bufferPtrSize = 0;  
     size_t movedBytes = 0;  
            
     bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);  
     bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));  
     memset((void *)bufferPtr, 0x0, bufferPtrSize);  
            
     const void *vkey = (const void *) [gkey UTF8String];  
     const void *vinitVec = (const void *) [gIv UTF8String];  
            
     ccStatus = CCCrypt(kCCEncrypt,  
                        kCCAlgorithm3DES,  
                        kCCOptionPKCS7Padding,  
                        vkey,  
                        kCCKeySize3DES,  
                        vinitVec,  
                        vplainText,  
                        plainTextBufferSize,  
                        (void *)bufferPtr,  
                        bufferPtrSize,  
                        &movedBytes);  
            
     NSData *myData = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)movedBytes];  
     NSString *result = [GTMBase64 stringByEncodingData:myData];  
     return result;  
}  
        
// 解密方法  
+ (NSString*)decrypt:(NSString*)encryptText {  
     NSData *encryptData = [GTMBase64 decodeData:[encryptText dataUsingEncoding:NSUTF8StringEncoding]];  
     size_t plainTextBufferSize = [encryptData length];  
     const void *vplainText = [encryptData bytes];  
            
     CCCryptorStatus ccStatus;  
     uint8_t *bufferPtr = NULL;  
     size_t bufferPtrSize = 0;  
     size_t movedBytes = 0;  
     bufferPtrSize = (plainTextBufferSize + kCCBlockSize3DES) & ~(kCCBlockSize3DES - 1);  
     bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));  
     memset((void *)bufferPtr, 0x0, bufferPtrSize);     
     const void *vkey = (const void *) [gkey UTF8String];  
     const void *vinitVec = (const void *) [gIv UTF8String];  
            
     ccStatus = CCCrypt(kCCDecrypt,  
                        kCCAlgorithm3DES,  
                        kCCOptionPKCS7Padding,  
                        vkey,  
                        kCCKeySize3DES,  
                        vinitVec,  
                        vplainText,  
                        plainTextBufferSize,  
                        (void *)bufferPtr,  
                        bufferPtrSize,  
                        &movedBytes);  
            
     NSString *result = [[[NSString alloc] initWithData:[NSData dataWithBytes:(const void *)bufferPtr   
                                 length:(NSUInteger)movedBytes] encoding:NSUTF8StringEncoding] autorelease];  
     return result;  
}  
        
@end

//
//  GTMBase64.h
//
//  Copyright 2006-2008 Google Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not
//  use this file except in compliance with the License.  You may obtain a copy
//  of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
//  License for the specific language governing permissions and limitations under
//  the License.

// David Lee make changes:
// Remove dependency on GTMDefines.h
// add some string to string function

#import <Foundation/Foundation.h>

// GTMBase64
//
/// Helper for handling Base64 and WebSafeBase64 encodings
//
/// The webSafe methods use different character set and also the results aren't
/// always padded to a multiple of 4 characters.  This is done so the resulting
/// data can be used in urls and url query arguments without needing any
/// encoding.  You must use the webSafe* methods together, the data does not
/// interop with the RFC methods.
//
@interface GTMBase64 : NSObject

//
// Standard Base64 (RFC) handling
//

// encodeData:
//
/// Base64 encodes contents of the NSData object.
//
/// Returns:
///   A new autoreleased NSData with the encoded payload.  nil for any error.
//
+(NSData *)encodeData:(NSData *)data;

// decodeData:
//
/// Base64 decodes contents of the NSData object.
//
/// Returns:
///   A new autoreleased NSData with the decoded payload.  nil for any error.
//
+(NSData *)decodeData:(NSData *)data;

// encodeBytes:length:
//
/// Base64 encodes the data pointed at by |bytes|.
//
/// Returns:
///   A new autoreleased NSData with the encoded payload.  nil for any error.
//
+(NSData *)encodeBytes:(const void *)bytes length:(NSUInteger)length;

// decodeBytes:length:
//
/// Base64 decodes the data pointed at by |bytes|.
//
/// Returns:
///   A new autoreleased NSData with the encoded payload.  nil for any error.
//
+(NSData *)decodeBytes:(const void *)bytes length:(NSUInteger)length;

// stringByEncodingData:
//
/// Base64 encodes contents of the NSData object.
//
/// Returns:
///   A new autoreleased NSString with the encoded payload.  nil for any error.
//
+(NSString *)stringByEncodingData:(NSData *)data;

// stringByEncodingBytes:length:
//
/// Base64 encodes the data pointed at by |bytes|.
//
/// Returns:
///   A new autoreleased NSString with the encoded payload.  nil for any error.
//
+(NSString *)stringByEncodingBytes:(const void *)bytes length:(NSUInteger)length;

// decodeString:
//
/// Base64 decodes contents of the NSString.
//
/// Returns:
///   A new autoreleased NSData with the decoded payload.  nil for any error.
//
+(NSData *)decodeString:(NSString *)string;

//
// Modified Base64 encoding so the results can go onto urls.
//
// The changes are in the characters generated and also allows the result to
// not be padded to a multiple of 4.
// Must use the matching call to encode/decode, won't interop with the
// RFC versions.
//

// webSafeEncodeData:padded:
//
/// WebSafe Base64 encodes contents of the NSData object.  If |padded| is YES
/// then padding characters are added so the result length is a multiple of 4.
//
/// Returns:
///   A new autoreleased NSData with the encoded payload.  nil for any error.
//
+(NSData *)webSafeEncodeData:(NSData *)data
                      padded:(BOOL)padded;

// webSafeDecodeData:
//
/// WebSafe Base64 decodes contents of the NSData object.
//
/// Returns:
///   A new autoreleased NSData with the decoded payload.  nil for any error.
//
+(NSData *)webSafeDecodeData:(NSData *)data;

// webSafeEncodeBytes:length:padded:
//
/// WebSafe Base64 encodes the data pointed at by |bytes|.  If |padded| is YES
/// then padding characters are added so the result length is a multiple of 4.
//
/// Returns:
///   A new autoreleased NSData with the encoded payload.  nil for any error.
//
+(NSData *)webSafeEncodeBytes:(const void *)bytes
                       length:(NSUInteger)length
                       padded:(BOOL)padded;

// webSafeDecodeBytes:length:
//
/// WebSafe Base64 decodes the data pointed at by |bytes|.
//
/// Returns:
///   A new autoreleased NSData with the encoded payload.  nil for any error.
//
+(NSData *)webSafeDecodeBytes:(const void *)bytes length:(NSUInteger)length;

// stringByWebSafeEncodingData:padded:
//
/// WebSafe Base64 encodes contents of the NSData object.  If |padded| is YES
/// then padding characters are added so the result length is a multiple of 4.
//
/// Returns:
///   A new autoreleased NSString with the encoded payload.  nil for any error.
//
+(NSString *)stringByWebSafeEncodingData:(NSData *)data
                                  padded:(BOOL)padded;

// stringByWebSafeEncodingBytes:length:padded:
//
/// WebSafe Base64 encodes the data pointed at by |bytes|.  If |padded| is YES
/// then padding characters are added so the result length is a multiple of 4.
//
/// Returns:
///   A new autoreleased NSString with the encoded payload.  nil for any error.
//
+(NSString *)stringByWebSafeEncodingBytes:(const void *)bytes
                                   length:(NSUInteger)length
                                   padded:(BOOL)padded;

// webSafeDecodeString:
//
/// WebSafe Base64 decodes contents of the NSString.
//
/// Returns:
///   A new autoreleased NSData with the decoded payload.  nil for any error.
//
+(NSData *)webSafeDecodeString:(NSString *)string;

// David Lee new added function
/// Returns:
// A new autoreleased NSString with Base64 encoded NSString
+(NSString *)stringByBase64String:(NSString *)base64String;

// David Lee new added function
/// Returns:
// A new autoreleased Base64 encoded NSString with  NSString
+(NSString *)base64StringBystring:(NSString *)string;
@end


//
//  GTMBase64.m
//
//  Copyright 2006-2008 Google Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not
//  use this file except in compliance with the License.  You may obtain a copy
//  of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
//  License for the specific language governing permissions and limitations under
//  the License.
// David Lee make changes:
// Remove dependency on GTMDefines.h
// add some string to string function

#import "GTMBase64.h"

static const char *kBase64EncodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char *kWebSafeBase64EncodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static const char kBase64PaddingChar = '=';
static const char kBase64InvalidChar = 99;

static const char kBase64DecodeChars[] = {
    // This array was generated by the following code:
    // #include <sys/time.h>
    // #include <stdlib.h>
    // #include <string.h>
    // main()
    // {
    //   static const char Base64[] =
    //     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    //   char *pos;
    //   int idx, i, j;
    //   printf("    ");
    //   for (i = 0; i < 255; i += 8) {
    //     for (j = i; j < i + 8; j++) {
    //       pos = strchr(Base64, j);
    //       if ((pos == NULL) || (j == 0))
    //         idx = 99;
    //       else
    //         idx = pos - Base64;
    //       if (idx == 99)
    //         printf(" %2d,     ", idx);
    //       else
    //         printf(" %2d/*%c*/,", idx, j);
    //     }
    //     printf("\n    ");
    //   }
    // }
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      62/*+*/, 99,      99,      99,      63/*/ */,
    52/*0*/, 53/*1*/, 54/*2*/, 55/*3*/, 56/*4*/, 57/*5*/, 58/*6*/, 59/*7*/,
    60/*8*/, 61/*9*/, 99,      99,      99,      99,      99,      99,
    99,       0/*A*/,  1/*B*/,  2/*C*/,  3/*D*/,  4/*E*/,  5/*F*/,  6/*G*/,
    7/*H*/,  8/*I*/,  9/*J*/, 10/*K*/, 11/*L*/, 12/*M*/, 13/*N*/, 14/*O*/,
    15/*P*/, 16/*Q*/, 17/*R*/, 18/*S*/, 19/*T*/, 20/*U*/, 21/*V*/, 22/*W*/,
    23/*X*/, 24/*Y*/, 25/*Z*/, 99,      99,      99,      99,      99,
    99,      26/*a*/, 27/*b*/, 28/*c*/, 29/*d*/, 30/*e*/, 31/*f*/, 32/*g*/,
    33/*h*/, 34/*i*/, 35/*j*/, 36/*k*/, 37/*l*/, 38/*m*/, 39/*n*/, 40/*o*/,
    41/*p*/, 42/*q*/, 43/*r*/, 44/*s*/, 45/*t*/, 46/*u*/, 47/*v*/, 48/*w*/,
    49/*x*/, 50/*y*/, 51/*z*/, 99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99
};

static const char kWebSafeBase64DecodeChars[] = {
    // This array was generated by the following code:
    // #include <sys/time.h>
    // #include <stdlib.h>
    // #include <string.h>
    // main()
    // {
    //   static const char Base64[] =
    //     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    //   char *pos;
    //   int idx, i, j;
    //   printf("    ");
    //   for (i = 0; i < 255; i += 8) {
    //     for (j = i; j < i + 8; j++) {
    //       pos = strchr(Base64, j);
    //       if ((pos == NULL) || (j == 0))
    //         idx = 99;
    //       else
    //         idx = pos - Base64;
    //       if (idx == 99)
    //         printf(" %2d,     ", idx);
    //       else
    //         printf(" %2d/*%c*/,", idx, j);
    //     }
    //     printf("\n    ");
    //   }
    // }
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      62/*-*/, 99,      99,
    52/*0*/, 53/*1*/, 54/*2*/, 55/*3*/, 56/*4*/, 57/*5*/, 58/*6*/, 59/*7*/,
    60/*8*/, 61/*9*/, 99,      99,      99,      99,      99,      99,
    99,       0/*A*/,  1/*B*/,  2/*C*/,  3/*D*/,  4/*E*/,  5/*F*/,  6/*G*/,
    7/*H*/,  8/*I*/,  9/*J*/, 10/*K*/, 11/*L*/, 12/*M*/, 13/*N*/, 14/*O*/,
    15/*P*/, 16/*Q*/, 17/*R*/, 18/*S*/, 19/*T*/, 20/*U*/, 21/*V*/, 22/*W*/,
    23/*X*/, 24/*Y*/, 25/*Z*/, 99,      99,      99,      99,      63/*_*/,
    99,      26/*a*/, 27/*b*/, 28/*c*/, 29/*d*/, 30/*e*/, 31/*f*/, 32/*g*/,
    33/*h*/, 34/*i*/, 35/*j*/, 36/*k*/, 37/*l*/, 38/*m*/, 39/*n*/, 40/*o*/,
    41/*p*/, 42/*q*/, 43/*r*/, 44/*s*/, 45/*t*/, 46/*u*/, 47/*v*/, 48/*w*/,
    49/*x*/, 50/*y*/, 51/*z*/, 99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99,
    99,      99,      99,      99,      99,      99,      99,      99
};


// Tests a character to see if it's a whitespace character.
//
// Returns:
//   YES if the character is a whitespace character.
//   NO if the character is not a whitespace character.
//
BOOL IsSpace(unsigned char c) {
    // we use our own mapping here because we don't want anything w/ locale
    // support.
    static BOOL kSpaces[256] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  // 0-9
        1, 1, 1, 1, 0, 0, 0, 0, 0, 0,  // 10-19
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 20-29
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0,  // 30-39
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 40-49
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 50-59
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 60-69
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 70-79
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 80-89
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 90-99
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 100-109
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 110-119
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 120-129
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 130-139
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 140-149
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 150-159
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 160-169
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 170-179
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 180-189
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 190-199
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 200-209
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 210-219
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 220-229
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 230-239
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 240-249
        0, 0, 0, 0, 0, 1,              // 250-255
    };
    return kSpaces[c];
}

// Calculate how long the data will be once it's base64 encoded.
//
// Returns:
//   The guessed encoded length for a source length
//
NSUInteger CalcEncodedLength(NSUInteger srcLen, BOOL padded) {
    NSUInteger intermediate_result = 8 * srcLen + 5;
    NSUInteger len = intermediate_result / 6;
    if (padded) {
        len = ((len + 3) / 4) * 4;
    }
    return len;
}

// Tries to calculate how long the data will be once it's base64 decoded.
// Unlike the above, this is always an upperbound, since the source data
// could have spaces and might end with the padding characters on them.
//
// Returns:
//   The guessed decoded length for a source length
//
NSUInteger GuessDecodedLength(NSUInteger srcLen) {
    return (srcLen + 3) / 4 * 3;
}


@interface GTMBase64 (PrivateMethods)

+(NSData *)baseEncode:(const void *)bytes
               length:(NSUInteger)length
              charset:(const char *)charset
               padded:(BOOL)padded;

+(NSData *)baseDecode:(const void *)bytes
               length:(NSUInteger)length
              charset:(const char*)charset
       requirePadding:(BOOL)requirePadding;

+(NSUInteger)baseEncode:(const char *)srcBytes
                 srcLen:(NSUInteger)srcLen
              destBytes:(char *)destBytes
                destLen:(NSUInteger)destLen
                charset:(const char *)charset
                 padded:(BOOL)padded;

+(NSUInteger)baseDecode:(const char *)srcBytes
                 srcLen:(NSUInteger)srcLen
              destBytes:(char *)destBytes
                destLen:(NSUInteger)destLen
                charset:(const char *)charset
         requirePadding:(BOOL)requirePadding;

@end


@implementation GTMBase64

//
// Standard Base64 (RFC) handling
//

+(NSData *)encodeData:(NSData *)data {
    return [self baseEncode:[data bytes]
                     length:[data length]
                    charset:kBase64EncodeChars
                     padded:YES];
}

+(NSData *)decodeData:(NSData *)data {
    return [self baseDecode:[data bytes]
                     length:[data length]
                    charset:kBase64DecodeChars
             requirePadding:YES];
}

+(NSData *)encodeBytes:(const void *)bytes length:(NSUInteger)length {
    return [self baseEncode:bytes
                     length:length
                    charset:kBase64EncodeChars
                     padded:YES];
}

+(NSData *)decodeBytes:(const void *)bytes length:(NSUInteger)length {
    return [self baseDecode:bytes
                     length:length
                    charset:kBase64DecodeChars
             requirePadding:YES];
}

+(NSString *)stringByEncodingData:(NSData *)data {
    NSString *result = nil;
    NSData *converted = [self baseEncode:[data bytes]
                                  length:[data length]
                                 charset:kBase64EncodeChars
                                  padded:YES];
    if (converted) {
        result = [[[NSString alloc] initWithData:converted
                                        encoding:NSASCIIStringEncoding] autorelease];
    }
    return result;
}

+(NSString *)stringByEncodingBytes:(const void *)bytes length:(NSUInteger)length {
    NSString *result = nil;
    NSData *converted = [self baseEncode:bytes
                                  length:length
                                 charset:kBase64EncodeChars
                                  padded:YES];
    if (converted) {
        result = [[[NSString alloc] initWithData:converted
                                        encoding:NSASCIIStringEncoding] autorelease];
    }
    return result;
}

+(NSData *)decodeString:(NSString *)string {
    NSData *result = nil;
    NSData *data = [string dataUsingEncoding:NSASCIIStringEncoding];
    if (data) {
        result = [self baseDecode:[data bytes]
                           length:[data length]
                          charset:kBase64DecodeChars
                   requirePadding:YES];
    }
    return result;
}

//
// Modified Base64 encoding so the results can go onto urls.
//
// The changes are in the characters generated and also the result isn't
// padded to a multiple of 4.
// Must use the matching call to encode/decode, won't interop with the
// RFC versions.
//

+(NSData *)webSafeEncodeData:(NSData *)data
                      padded:(BOOL)padded {
    return [self baseEncode:[data bytes]
                     length:[data length]
                    charset:kWebSafeBase64EncodeChars
                     padded:padded];
}

+(NSData *)webSafeDecodeData:(NSData *)data {
    return [self baseDecode:[data bytes]
                     length:[data length]
                    charset:kWebSafeBase64DecodeChars
             requirePadding:NO];
}

+(NSData *)webSafeEncodeBytes:(const void *)bytes
                       length:(NSUInteger)length
                       padded:(BOOL)padded {
    return [self baseEncode:bytes
                     length:length
                    charset:kWebSafeBase64EncodeChars
                     padded:padded];
}

+(NSData *)webSafeDecodeBytes:(const void *)bytes length:(NSUInteger)length {
    return [self baseDecode:bytes
                     length:length
                    charset:kWebSafeBase64DecodeChars
             requirePadding:NO];
}

+(NSString *)stringByWebSafeEncodingData:(NSData *)data
                                  padded:(BOOL)padded {
    NSString *result = nil;
    NSData *converted = [self baseEncode:[data bytes]
                                  length:[data length]
                                 charset:kWebSafeBase64EncodeChars
                                  padded:padded];
    if (converted) {
        result = [[[NSString alloc] initWithData:converted
                                        encoding:NSASCIIStringEncoding] autorelease];
    }
    return result;
}

+(NSString *)stringByWebSafeEncodingBytes:(const void *)bytes
                                   length:(NSUInteger)length
                                   padded:(BOOL)padded {
    NSString *result = nil;
    NSData *converted = [self baseEncode:bytes
                                  length:length
                                 charset:kWebSafeBase64EncodeChars
                                  padded:padded];
    if (converted) {
        result = [[[NSString alloc] initWithData:converted
                                        encoding:NSASCIIStringEncoding] autorelease];
    }
    return result;
}

+(NSData *)webSafeDecodeString:(NSString *)string {
    NSData *result = nil;
    NSData *data = [string dataUsingEncoding:NSASCIIStringEncoding];
    if (data) {
        result = [self baseDecode:[data bytes]
                           length:[data length]
                          charset:kWebSafeBase64DecodeChars
                   requirePadding:NO];
    }
    return result;
}

// David Lee new added function
/// Returns:
// A new autoreleased NSString with Base64 encoded NSString
+(NSString *)stringByBase64String:(NSString *)base64String
{
    NSString *sourceString = [[[NSString alloc] initWithData:[GTMBase64 decodeData:[base64String dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO]] encoding:NSUTF8StringEncoding] autorelease];
    return sourceString;
}

// David Lee new added function
/// Returns:
// A new autoreleased Base64 encoded NSString with NSString
+(NSString *)base64StringBystring:(NSString *)string
{
    NSString *base64String = [[[NSString alloc] initWithData:[GTMBase64 encodeData:[string dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO]] encoding:NSUTF8StringEncoding] autorelease];
    return base64String;
}

@end

@implementation GTMBase64 (PrivateMethods)

//
// baseEncode:length:charset:padded:
//
// Does the common lifting of creating the dest NSData.  it creates & sizes the
// data for the results.  |charset| is the characters to use for the encoding
// of the data.  |padding| controls if the encoded data should be padded to a
// multiple of 4.
//
// Returns:
//   an autorelease NSData with the encoded data, nil if any error.
//
+(NSData *)baseEncode:(const void *)bytes
               length:(NSUInteger)length
              charset:(const char *)charset
               padded:(BOOL)padded {
    // how big could it be?
    NSUInteger maxLength = CalcEncodedLength(length, padded);
    // make space
    NSMutableData *result = [NSMutableData data];
    [result setLength:maxLength];
    // do it
    NSUInteger finalLength = [self baseEncode:bytes
                                       srcLen:length
                                    destBytes:[result mutableBytes]
                                      destLen:[result length]
                                      charset:charset
                                       padded:padded];
    if (finalLength) {
        NSAssert(finalLength == maxLength, @"how did we calc the length wrong?");
    } else {
        // shouldn't happen, this means we ran out of space
        result = nil;
    }
    return result;
}

//
// baseDecode:length:charset:requirePadding:
//
// Does the common lifting of creating the dest NSData.  it creates & sizes the
// data for the results.  |charset| is the characters to use for the decoding
// of the data.
//
// Returns:
//   an autorelease NSData with the decoded data, nil if any error.
//
//
+(NSData *)baseDecode:(const void *)bytes
               length:(NSUInteger)length
              charset:(const char *)charset
       requirePadding:(BOOL)requirePadding {
    // could try to calculate what it will end up as
    NSUInteger maxLength = GuessDecodedLength(length);
    // make space
    NSMutableData *result = [NSMutableData data];
    [result setLength:maxLength];
    // do it
    NSUInteger finalLength = [self baseDecode:bytes
                                       srcLen:length
                                    destBytes:[result mutableBytes]
                                      destLen:[result length]
                                      charset:charset
                               requirePadding:requirePadding];
    if (finalLength) {
        if (finalLength != maxLength) {
            // resize down to how big it was
            [result setLength:finalLength];
        }
    } else {
        // either an error in the args, or we ran out of space
        result = nil;
    }
    return result;
}

//
// baseEncode:srcLen:destBytes:destLen:charset:padded:
//
// Encodes the buffer into the larger.  returns the length of the encoded
// data, or zero for an error.
// |charset| is the characters to use for the encoding
// |padded| tells if the result should be padded to a multiple of 4.
//
// Returns:
//   the length of the encoded data.  zero if any error.
//
+(NSUInteger)baseEncode:(const char *)srcBytes
                 srcLen:(NSUInteger)srcLen
              destBytes:(char *)destBytes
                destLen:(NSUInteger)destLen
                charset:(const char *)charset
                 padded:(BOOL)padded {
    if (!srcLen || !destLen || !srcBytes || !destBytes) {
        return 0;
    }
    
    char *curDest = destBytes;
    const unsigned char *curSrc = (const unsigned char *)(srcBytes);
    
    // Three bytes of data encodes to four characters of cyphertext.
    // So we can pump through three-byte chunks atomically.
    while (srcLen > 2) {
        // space?
        NSAssert(destLen >= 4, @"our calc for encoded length was wrong");
        curDest[0] = charset[curSrc[0] >> 2];
        curDest[1] = charset[((curSrc[0] & 0x03) << 4) + (curSrc[1] >> 4)];
        curDest[2] = charset[((curSrc[1] & 0x0f) << 2) + (curSrc[2] >> 6)];
        curDest[3] = charset[curSrc[2] & 0x3f];
        
        curDest += 4;
        curSrc += 3;
        srcLen -= 3;
        destLen -= 4;
    }
    
    // now deal with the tail (<=2 bytes)
    switch (srcLen) {
        case 0:
            // Nothing left; nothing more to do.
            break;
        case 1:
            // One byte left: this encodes to two characters, and (optionally)
            // two pad characters to round out the four-character cypherblock.
            NSAssert(destLen >= 2, @"our calc for encoded length was wrong");
            curDest[0] = charset[curSrc[0] >> 2];
            curDest[1] = charset[(curSrc[0] & 0x03) << 4];
            curDest += 2;
            destLen -= 2;
            if (padded) {
                NSAssert(destLen >= 2, @"our calc for encoded length was wrong");
                curDest[0] = kBase64PaddingChar;
                curDest[1] = kBase64PaddingChar;
                curDest += 2;
            }
            break;
        case 2:
            // Two bytes left: this encodes to three characters, and (optionally)
            // one pad character to round out the four-character cypherblock.
            NSAssert(destLen >= 3, @"our calc for encoded length was wrong");
            curDest[0] = charset[curSrc[0] >> 2];
            curDest[1] = charset[((curSrc[0] & 0x03) << 4) + (curSrc[1] >> 4)];
            curDest[2] = charset[(curSrc[1] & 0x0f) << 2];
            curDest += 3;
            destLen -= 3;
            if (padded) {
                NSAssert(destLen >= 1, @"our calc for encoded length was wrong");
                curDest[0] = kBase64PaddingChar;
                curDest += 1;
            }
            break;
    }
    // return the length
    return (curDest - destBytes);
}

//
// baseDecode:srcLen:destBytes:destLen:charset:requirePadding:
//
// Decodes the buffer into the larger.  returns the length of the decoded
// data, or zero for an error.
// |charset| is the character decoding buffer to use
//
// Returns:
//   the length of the encoded data.  zero if any error.
//
+(NSUInteger)baseDecode:(const char *)srcBytes
                 srcLen:(NSUInteger)srcLen
              destBytes:(char *)destBytes
                destLen:(NSUInteger)destLen
                charset:(const char *)charset
         requirePadding:(BOOL)requirePadding {
    if (!srcLen || !destLen || !srcBytes || !destBytes) {
        return 0;
    }
    
    int decode;
    NSUInteger destIndex = 0;
    int state = 0;
    char ch = 0;
    while (srcLen-- && (ch = *srcBytes++) != 0)  {
        if (IsSpace(ch))  // Skip whitespace
            continue;
        
        if (ch == kBase64PaddingChar)
            break;
        
        decode = charset[(unsigned int)ch];
        if (decode == kBase64InvalidChar)
            return 0;
        
        // Four cyphertext characters decode to three bytes.
        // Therefore we can be in one of four states.
        switch (state) {
            case 0:
                // We're at the beginning of a four-character cyphertext block.
                // This sets the high six bits of the first byte of the
                // plaintext block.
                NSAssert(destIndex < destLen, @"our calc for decoded length was wrong");
                destBytes[destIndex] = decode << 2;
                state = 1;
                break;
            case 1:
                // We're one character into a four-character cyphertext block.
                // This sets the low two bits of the first plaintext byte,
                // and the high four bits of the second plaintext byte.
                NSAssert((destIndex+1) < destLen, @"our calc for decoded length was wrong");
                destBytes[destIndex] |= decode >> 4;
                destBytes[destIndex+1] = (decode & 0x0f) << 4;
                destIndex++;
                state = 2;
                break;
            case 2:
                // We're two characters into a four-character cyphertext block.
                // This sets the low four bits of the second plaintext
                // byte, and the high two bits of the third plaintext byte.
                // However, if this is the end of data, and those two
                // bits are zero, it could be that those two bits are
                // leftovers from the encoding of data that had a length
                // of two mod three.
                NSAssert((destIndex+1) < destLen, @"our calc for decoded length was wrong");
                destBytes[destIndex] |= decode >> 2;
                destBytes[destIndex+1] = (decode & 0x03) << 6;
                destIndex++;
                state = 3;
                break;
            case 3:
                // We're at the last character of a four-character cyphertext block.
                // This sets the low six bits of the third plaintext byte.
                NSAssert(destIndex < destLen, @"our calc for decoded length was wrong");
                destBytes[destIndex] |= decode;
                destIndex++;
                state = 0;
                break;
        }
    }
    
    // We are done decoding Base-64 chars.  Let's see if we ended
    //      on a byte boundary, and/or with erroneous trailing characters.
    if (ch == kBase64PaddingChar) {               // We got a pad char
        if ((state == 0) || (state == 1)) {
            return 0;  // Invalid '=' in first or second position
        }
        if (srcLen == 0) {
            if (state == 2) { // We run out of input but we still need another '='
                return 0;
            }
            // Otherwise, we are in state 3 and only need this '='
        } else {
            if (state == 2) {  // need another '='
                while ((ch = *srcBytes++) && (srcLen-- > 0)) {
                    if (!IsSpace(ch))
                        break;
                }
                if (ch != kBase64PaddingChar) {
                    return 0;
                }
            }
            // state = 1 or 2, check if all remain padding is space
            while ((ch = *srcBytes++) && (srcLen-- > 0)) {
                if (!IsSpace(ch)) {
                    return 0;
                }
            }
        }
    } else {
        // We ended by seeing the end of the string.
        
        if (requirePadding) {
            // If we require padding, then anything but state 0 is an error.
            if (state != 0) {
                return 0;
            }
        } else {
            // Make sure we have no partial bytes lying around.  Note that we do not
            // require trailing '=', so states 2 and 3 are okay too.
            if (state == 1) {
                return 0;
            }
        }
    }
    
    // If then next piece of output was valid and got written to it means we got a
    // very carefully crafted input that appeared valid but contains some trailing
    // bits past the real length, so just toss the thing.
    if ((destIndex < destLen) &&
        (destBytes[destIndex] != 0)) {
        return 0;
    }
    
    return destIndex;
}

@end

```
