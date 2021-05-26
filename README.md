 # Delphi Encryption Compendium

 ## Note
If you're looking to do cryptography in Pascal on ARM, PowerPC or other exotic platforms, you've come to the right place. If you're a Delphi user or want to use more modern ciphers and hash algorithms such as SHA-3, please take a look at the [official DEC repository](https://github.com/MHumm/DelphiEncryptionCompendium).

 ## Introduction
The Delphi Encryption Compendium (DEC) is a cryptographic library for Delphi, C++ Builder and Free Pascal. It was originally developed by Hagen Reddmann, made compatible with Delphi 2009 by Arvid Winkelsdorf, and has now been ported to Free Pascal.

The following changes have been made with respect to the 2008 release:
* Added a pure Pascal version for all methods that were previously coded in x86 assembly only.
* Syntax compatibility with Free Pascal in Delphi mode.
* Un-nested procedures in all places where they were passed as function pointers (which is not portable, not even in Delphi Win64).
* Modified shift operand for all shl/shr operations to be in range 0-31 (architectures like ARM do not support shifts >= 32).
* Test cases in DECTest are handled by a class now in order to get rid of an assembly hack to call nested procedures.
* Made all algorithms compatible with big endian processors via conditional compilation.

The following environments have been tested:
* Delphi XE2 Win32
* Delphi 10.2 Win32 & Win64
* FPC 2.6.4 Linux x86_64
* FPC 3.1.1 Linux ARM
* FPC 3.1.1 Win32
* FPC 3.2.0 Win64
* FPC 3.2.0 Linux PPC

Technically Delphi 7+ and FPC 2.6+ should be compatible (possibly very minor changes required for old versions).

 ## License
This project is licensed under a MIT/Freeware license. You are free to use the library for personal and commercial use but at your own risk. See LICENSE for details.

 ## Library overview
DEC mainly consists of the following units:
* CPU.pas: Queries information about an x86-based processor (Win32/Win64 only).
* DECCRC.pas: Cyclic Redundance Check implementation for many common lengths and polynomials.
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
 ### AES-CBC-128 encode/decode example:
 ```
const
  STATIC_KEY: array[0..15] of Byte = (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
var
  IV: array[0..15] of Byte;
  Plaintext: Binary;
  Ciphertext: TBytes;
begin
  RandomSeed;
  Plaintext := 'abcdefghijklmnopqrstuvwxyz';
  with TCipher_Rijndael.Create do
    try
      Mode := cmCBCx;
      RandomBuffer(IV, 16);
      Init(STATIC_KEY, 16, IV, 16); 
      SetLength(Ciphertext, Length(Plaintext));
      Encode(Plaintext[1], Ciphertext[0], Length(Plaintext));
      Done; // only needed when same object will be used for further operations
      FillChar(Plaintext[1], Length(Plaintext), 0);
      Decode(Ciphertext[0], Plaintext[1], Length(Ciphertext));
      Assert(Plaintext = 'abcdefghijklmnopqrstuvwxyz');
    finally
      Free;
    end;
end;
```
Note: If the plaintext isn't padded, DEC will pad the last truncated block with CFB8! PKCS padding is not supported by DEC. Using DEC in conjunction with other crypto libraries is of course possible, but you need to make sure to preprocess (i.e. pad) the plaintext properly.

Also note: DEC's Binary type is defined as RawByteString. If you are in a unicode environment (e.g. Delphi 2009+), care is advised when dealing with variables of type ``string``. Never directly pass them into a function that takes Binary!

### SHA-256 examples with formatting
```
var
  InputBuf: TBytes;
  InputRawStr, Hash: Binary;
begin
  SetLength(InputBuf, 4);
  FillChar(InputBuf[0], 4, $AA);
  Hash := THash_SHA256.CalcBuffer(InputBuf[0], 4, TFormat_MIME64);
  // -> 2+0UzrAB0RDXZrkBPTtbv/rWkVR1qboHky0qwFeUTAQ=
  InputRawStr := 'My message';
  Hash := THash_SHA256.CalcBinary(InputRawStr, TFormat_HEXL);
  // -> acc147c887e3b838ebf870c8779989fa8283eff5787b57f1acb35cac63244a81
  Hash := THash_SHA256.CalcBinary(InputRawStr, TFormat_Copy);
  // -> Hash contains ac c1 47 ... raw bytes. Can be copied to a 32 bytes array using Move(Hash[1], HashBytes[0], 32);
end;
```

Each hash class also has functions called KDF2 and KDFx for key derivation (e.g. for use as session keys in ciphers).

### Standalone formatting
```
  Writeln(TFormat_MIME64.Encode('My message'));
  // -> TXkgbWVzc2FnZQ==
  Writeln(TFormat_MIME64.Decode('TXkgbWVzc2FnZQ=='));
  // -> My message
  Writeln(TFormat_PGP.Encode('Hello, how are you today?'));
  // -> SGVsbG8sIGhvdyBhcmUgeW91IHRvZGF5Pw== <line break> =nUAA  
```

Encode and Decode are both overloaded to also take an untyped input buffer.
