{ This file was automatically created by Lazarus. Do not edit!
  This source is only used to compile and install the package.
 }

unit DEC;

{$warn 5023 off : no warning about unused units}
interface

uses
  DECCPU, DECCipher, DECCRC, DECData, DECFmt, DECHash, DECRandom, DECUtil, 
  LazarusPackageIntf;

implementation

procedure Register;
begin
end;

initialization
  RegisterPackage('DEC', @Register);
end.
