 # Delphi Encryption Compendium
 ## Introduction
The Delphi Encryption Compendium (DEC) is a cryptographic library for Delphi, C++ Builder and Free Pascal. It was originally developed by Hagen Reddmann, made compatible with Delphi 2009 by Arvid Winkelsdorf, and has now been ported to Free Pascal.

The following changes have been made with respect to the 2008 release:
* Added a pure Pascal version for all methods that were previously coded in x86 assembly only.
* Syntax compatibility with Free Pascal in Delphi mode.
* Un-nested procedures in all places where they were passed as function pointers (which is not portable, not even in Delphi Win64).
* Modified shift operand for all shl/shr operations to be in range 0-31 (architectures like ARM do not support shifts >= 32).
* Test cases in DECTest are handled by a class now in order to get rid of an assembly hack to call nested procedures.

The following environments have been tested:
* Delphi XE2 Win32
* Delphi 10.2 Win32 & Win64
* FPC 2.6.4 Linux x86_64
* FPC 3.1.1 Linux ARM
* FPC 3.1.1 Win32

Technically Delphi 7+ and FPC 2.6+ should be compatible (possibly very minor changes required for old versions).

 ## License
This project is licensed under a MIT/Freeware license. You are free to use the library for personal and commercial use but at your own risk. See LICENSE for details.

 ## Library overview
DEC mainly consists of the following units:
* CPU.pas: Queries information about an x86-based processor (Win32/Win64 only).
* CRC.pas: Cyclic Redundance Check implementation for many common lengths and polynomials.
* DECCipher.pas: Implementation of symmetric ciphers and most common operation modes.
* DECFmt.pas: Formatting classes for all common data formats.
* DECHash.pas: Implementation of hash functions.
* DECRandom.pas: Secure protected Random Number Generator based on Yarrow.
* DECUtil.pas: Utility functions for dealing with buffers, random numbers etc.

Furthermore the DECTest project is included, which provides test cases for all algorithms.

The original DEC also contained the units ASN1 and TypeInfoEx - those are not required for the core functionality of DEC and have not been ported. If you need them, please get them from an older release.

 ## Features
 ### Symmetric ciphers
 * Blowfish
 * Twofish
 * IDEA
 * Cast128, Cast256
 * Mars
 * RC2, RC4, RC5, RC6
 * Rijndael / AES
 * Square
 * SCOP
 * Sapphire
 * 1DES, 2DES, 3DES, 2DDES, 3DDES, 3TDES
 * 3Way
 * Gost
 * Misty
 * NewDES
 * Q128
 * SAFER
 * Shark
 * Skipjack
 * TEA, TEAN
 
 ### Block cipher operation modes
 * CTSx
 * CBCx
 * CFB8
 * CFBx
 * OFB8
 * OFBx
 * CFSx
 * ECBx
 
Check DECCipher.pas for more details on these modes.

 ### Hash functions
* MD2, MD4, MD5
* RipeMD128, RipeMD160, RipeMD256, RipeMD320
* SHA, SHA1, SHA256, SHA384, SHA512
* Haval128, Haval160, Haval192, Haval224, Haval256
* Tiger
* Panama
* Whirlpool, Whirlpool1
* Square
* Snefru128, Snefru256
* Sapphire

 ### Data formatting
* 1:1 Copy
* Hexadecimal Uppercase
* Hexadecimal Lowercase
* MIME/Base32
* MIME/Base64
* PGP (MIME/Base64 with PGP Checksums)
* UU Encode
* XX Encode
* Escaped Strings

 ## Usage examples
 TODO
