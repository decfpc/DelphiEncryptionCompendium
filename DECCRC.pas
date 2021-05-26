{*****************************************************************************

  Delphi Encryption Compendium (DEC Part I)
  Version 5.3 for Delphi 7 - 10.4 or higher/FPC 2.6 or higher

  Remarks:          Freeware, Copyright must be included

  Original Author:  (c) 2006 Hagen Reddmann, HaReddmann [at] T-Online [dot] de
  Modifications:    (c) 2008 Arvid Winkelsdorf, info [at] digivendo [dot] de
                    (c) 2017, 2021 decfpc

  Description:      threadsafe CRC Checksum functions as single unit.
                    Implementation of Cyclic Redundance Checking.
                    Supports ALL possible CRCs, per default are follow
                    Standard CRCs supported:
                      CRC-8, CRC-10, CRC-12 (Mobil Telephone),
                      CRC-16, CRC-16-CCITT, CRC-16-ZModem,
                      CRC-24 (PGP's MIME64 Armor CRC),
                      CRC-32, CRC-32-CCITT and CRC-32-ZModem.

  Note:
  - this unit should be fully PIC safe, means Kylix compatible
  - this unit consume only 728 - max. 952 Bytes code if all functions are used
  - 2 * 4 Bytes in Datasegment (BSS) are used
  - on runtime it need two memoryblocks of size 2x1056 bytes if
    CRC16() and CRC32() are called, if none of both is used no memory are need
  - on multithread application and the use of CRC16() or CRC32() You should call
    CRCInitThreadSafe at initialization of the application or before threaded
    use of CRC16() or CRC32().
  - yes, we could it realy more speedup, as example loop unrolling, but then the
    code grows and i wanted a good compromiss between speed and size.

 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*****************************************************************************}

unit DECCRC;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}
{$I Ver.inc}

interface

{
how to use:

var
  CRC16: Word;
begin
  CRC16 := CRCCalc(CRC_16, Data, SizeOf(Data)); // all in one
end;

var
  CRC: TCRCDef;
  CRC32: Cardinal;
begin
  CRCInit(CRC, CRC_32);                         // setup CRC data structure
  CRCCode(CRC, Data, SizeOf(Data));             // returns correct CRC32 for this Data
  CRCCode(CRC, PChar(String)^, Length(String) * SizeOf(Char)); // returns correct CRC32 for String AND CRC.CRC holds intermediate
  CRC32 := CRCDone(CRC);                        // returns correct CRC32 for Data + String
  // after CRCDone we can restart a new calculation  
end;

  above examples are fully threadsafe and require ~ $0420 Bytes Stack space.
}

type
  // CRC Definitions Structure
  PCRCDef = ^TCRCDef;
  TCRCDef = packed record              // don't reorder or change this structure
    Table: array[0..255] of Cardinal;  // Lookuptable, precomputed in CRCSetup
    CRC: Cardinal;                     // intermediate CRC
    Inverse: LongBool;                 // is this Polynomial a inverse function
    Shift: Cardinal;                   // Shift Value for CRCCode, more speed
    InitVector: Cardinal;              // Startvalue of CRC Computation
    FinalVector: Cardinal;             // final XOR Vector of computed CRC
    Mask: Cardinal;                    // precomputed AND Mask of computed CRC
    Bits: Cardinal;                    // Bitsize of CRC
    Polynomial: Cardinal;              // used Polynomial
  end;                                 // SizeOf(TCRCDef) = 1056 = 0420h

  // predefined Standard CRC Types
  TCRCType = (CRC_8, CRC_10, CRC_12, CRC_16, CRC_16CCITT, CRC_16XModem, CRC_24,
              CRC_32, CRC_32CCITT, CRC_32ZModem);
type
  TReadMethod = function(var Buffer; Count: LongInt): LongInt of object;

// calculates a CRC over Buffer with Size Bytes Length, used Algo in CRCType, all is done in one Step
function CRCCalc(CRCType: TCRCType; const Buffer; Size: Cardinal): Cardinal;

// use a callback
function CRCCalcEx(CRCType: TCRCType; ReadMethod: TReadMethod; Size: Cardinal = $FFFFFFFF): Cardinal;

// initialize CRC Definition with CRCType Standard CRC
function CRCInit(var CRCDef: TCRCDef; CRCType: TCRCType): Boolean;

// initilaize CRC Definition with a custom Algorithm
function CRCSetup(var CRCDef: TCRCDef; Polynomial, Bits, InitVector, FinalVector: Cardinal; Inverse: LongBool): Boolean;

// process over Buffer with Size Bytes Length a CRC definied in CRCDef.
// Result is actual computed CRC with correction, same as CRCDone(),
// CRCDef.CRC holds the actual computed CRC, a second/more call to CRCCode
// computes than both/more buffers as one buffer.
function CRCCode(var CRCDef: TCRCDef; const Buffer; Size: Cardinal): Cardinal;

// use a callback, eg. TStream.Read(). I hate D4 because they don't love overloaded procedures here
function CRCCodeEx(var CRCDef: TCRCDef; ReadMethod: TReadMethod; Size: Cardinal = $FFFFFFFF): Cardinal;

// retruns corrected CRC as definied in CRCDef, and reset CRCDef.CRC to InitVector
function CRCDone(var CRCDef: TCRCDef): Cardinal;

// predefined CRC16-Standard, call CRC := CRC16(0, Data, SizeOf(Data));
function CRC16(CRC: Word; const Buffer; Size: Cardinal): Word;

// predefined CRC32-CCITT, call CRC := CRC32(0, Data, SizeOf(Data));
function CRC32(CRC: Cardinal; const Buffer; Size: Cardinal): Cardinal;

// make it threadsafe
procedure CRCInitThreadSafe;

implementation

function ROL(Value, Count: Cardinal): Cardinal;
begin
  // Assert(Count < 32);
  Result := Value shl Count;
  Result := Result or (Value shr (32 - Count));
end;

function ROR(Value, Count: Cardinal): Cardinal;
begin
  // Assert(Count < 32);
  Result := Value shr Count;
  Result := Result or (Value shl (32 - Count));
end;

function CRCSetup(var CRCDef: TCRCDef; Polynomial, Bits, InitVector,
  FinalVector: Cardinal; Inverse: LongBool): Boolean; {$IFDEF UseASM86}register;{$ENDIF}
{$IFDEF UseASM86}
asm // initialize CRCDef according to the parameters, calculate the lookup table
       CMP   ECX,8
       JB    @@8
       PUSH  EBX
       PUSH  EDI
       PUSH  ESI
       MOV   [EAX].TCRCDef.Polynomial,EDX
       MOV   [EAX].TCRCDef.Bits,ECX
       MOV   EBX,InitVector
       MOV   EDI,FinalVector
       MOV   ESI,Inverse
       MOV   [EAX].TCRCDef.CRC,EBX
       MOV   [EAX].TCRCDef.InitVector,EBX
       MOV   [EAX].TCRCDef.FinalVector,EDI
       MOV   [EAX].TCRCDef.Inverse,ESI
       XOR   EDI,EDI
       LEA   EBX,[ECX - 8]
       SUB   ECX,32
       DEC   EDI
       NEG   ECX
       SHR   EDI,CL
       MOV   [EAX].TCRCDef.Shift,EBX
       MOV   [EAX].TCRCDef.Mask,EDI
       TEST  ESI,ESI
       JZ    @@5
       XOR   EBX,EBX
       MOV   ECX,[EAX].TCRCDef.Bits
@@1:   SHR   EDX,1
       ADC   EBX,EBX
       DEC   ECX
       JNZ   @@1
       NOP
       MOV   ECX,255
       NOP
@@20:  MOV   EDX,ECX
       SHR   EDX,1
       JNC   @@21
       XOR   EDX,EBX
@@21:  SHR   EDX,1
       JNC   @@22
       XOR   EDX,EBX
@@22:  SHR   EDX,1
       JNC   @@23
       XOR   EDX,EBX
@@23:  SHR   EDX,1
       JNC   @@24
       XOR   EDX,EBX
@@24:  SHR   EDX,1
       JNC   @@25
       XOR   EDX,EBX
@@25:  SHR   EDX,1
       JNC   @@26
       XOR   EDX,EBX
@@26:  SHR   EDX,1
       JNC   @@27
       XOR   EDX,EBX
@@27:  SHR   EDX,1
       JNC   @@28
       XOR   EDX,EBX
@@28:  MOV   [EAX + ECX * 4],EDX
       DEC   ECX
       JNL   @@20
       JMP   @@7
@@5:   AND   EDX,EDI
       ROL   EDX,CL
       MOV   EBX,255
// can be coded branchfree       
@@60:  MOV   ESI,EBX
       SHL   ESI,25
       JNC   @@61
       XOR   ESI,EDX
@@61:  ADD   ESI,ESI
       JNC   @@62
       XOR   ESI,EDX
@@62:  ADD   ESI,ESI
       JNC   @@63
       XOR   ESI,EDX
@@63:  ADD   ESI,ESI
       JNC   @@64
       XOR   ESI,EDX
@@64:  ADD   ESI,ESI
       JNC   @@65
       XOR   ESI,EDX
@@65:  ADD   ESI,ESI
       JNC   @@66
       XOR   ESI,EDX
@@66:  ADD   ESI,ESI
       JNC   @@67
       XOR   ESI,EDX
@@67:  ADD   ESI,ESI
       JNC   @@68
       XOR   ESI,EDX
@@68:  ROR   ESI,CL
       MOV   [EAX + EBX * 4],ESI
       DEC   EBX
       JNL   @@60
@@7:   POP   ESI
       POP   EDI
       POP   EBX
@@8:   CMC
       SBB   EAX,EAX
       NEG   EAX
end;
{$ELSE}
var
  n, k, c, poly, cold: Cardinal;
begin
  Result := Bits >= 8;
  if Result then
  begin
    CRCDef.Polynomial := Polynomial;
    CRCDef.Bits := Bits;
    CRCDef.CRC := InitVector;
    CRCDef.InitVector := InitVector;
    CRCDef.FinalVector := FinalVector;
    CRCDef.Inverse := Inverse;
    CRCDef.Shift := Bits - 8;
    CRCDef.Mask := $FFFFFFFF shr (32 - Bits);

    if Inverse then
    begin
      poly := 0;
      for n := Bits - 1 downto 0 do
      begin
        Inc(poly, poly + (Polynomial and 1));
        Polynomial := Polynomial shr 1;
      end;

      for n := 255 downto 0 do
      begin
        c := n;
        for k := 0 to 7 do
        begin
          if (c and 1) <> 0 then
            c := poly xor (c shr 1)
          else
            c := (c shr 1);
        end;
        CRCDef.Table[n] := c;
      end;
    end
    else
    begin
      poly := ROL(CRCDef.Mask and Polynomial, 32 - Bits);

      for n := 255 downto 0 do
      begin
        c := n shl 25;
        if n and $80 <> 0 then
          c := c xor poly;

        for k := 0 to 6 do
        begin
          cold := c;
          Inc(c, c);
          if cold > c then
            c := c xor poly;
        end;
        CRCDef.Table[n] := ROR(c, 32 - Bits);
      end;
      Result := CRCDef.Table[0] and $80000000 = 0; // CF of last ROR
    end;
  end;
end;
{$ENDIF}

function CRCCode(var CRCDef: TCRCDef; const Buffer;
  Size: Cardinal): Cardinal; {$IFDEF UseASM86}register;{$ENDIF}
{$IFDEF UseASM86}
asm // do the CRC computation
       JECXZ @@5
       TEST  EDX,EDX
       JZ    @@5
       PUSH  ESI
       PUSH  EBX
       MOV   ESI,EAX
       CMP   [EAX].TCRCDef.Inverse,0
       MOV   EAX,[ESI].TCRCDef.CRC
       JZ    @@2
       XOR   EBX,EBX
@@1:   MOV   BL,[EDX]
       XOR   BL,AL
       SHR   EAX,8
       INC   EDX
       XOR   EAX,[ESI + EBX * 4]
       DEC   ECX
       JNZ   @@1
       JMP   @@4
@@2:   PUSH  EDI
       MOV   EBX,EAX
       MOV   EDI,ECX
       MOV   ECX,[ESI].TCRCDef.Shift
       MOV   EBX,EAX
@@3:   SHR   EBX,CL
       SHL   EAX,8
       XOR   BL,[EDX]
       INC   EDX
       MOVZX EBX,BL
       XOR   EAX,[ESI + EBX * 4]
       DEC   EDI
       MOV   EBX,EAX
       JNZ   @@3
       POP   EDI
@@4:   MOV   [ESI].TCRCDef.CRC,EAX
       XOR   EAX,[ESI].TCRCDef.FinalVector
       AND   EAX,[ESI].TCRCDef.Mask
       POP   EBX
       POP   ESI
       RET
@@5:   MOV   EAX,[EAX].TCRCDef.CRC
end;
{$ELSE}
var
  B: PByte;
  Shift, CRC: Cardinal;
begin
  B := PByte(@Buffer);
  if (Size = 0) or (B = nil) then
    Exit(CRCDef.CRC);

  CRC := CRCDef.CRC;
  if not CRCDef.Inverse then
  begin
    Shift := CRCDef.Shift;
    repeat
      CRC := CRCDef.Table[B^ xor Byte(CRC shr Shift)] xor (CRC shl 8);
      Inc(B);
      Dec(Size);
    until Size = 0;
  end
  else
  begin
    repeat
      CRC := CRCDef.Table[B^ xor Byte(CRC)] xor (CRC shr 8);
      Inc(B);
      Dec(Size);
    until Size = 0;
  end;

  CRCDef.CRC := CRC;
  Result := CRCDef.Mask and (CRCDef.FinalVector xor CRC);
end;
{$ENDIF}

function CRCCodeEx(var CRCDef: TCRCDef; ReadMethod: TReadMethod; Size: Cardinal): Cardinal;
{$IFDEF FPC}{$push}{$warn 5057 off}{$ENDIF}
var
  Buffer: array[0..1023] of Char;
  Count: LongInt;
begin
  repeat
    if Size > SizeOf(Buffer) then
      Count := SizeOf(Buffer)
    else
      Count := Size;
    Count := ReadMethod(Buffer, Count);
    Result := CRCCode(CRCDef, Buffer, Count);
    Dec(Size, Count);
  until (Size = 0) or (Count = 0);
end;
{$IFDEF FPC}{$pop}{$ENDIF}

{$IFOPT O-}{$O+}{$DEFINE NoOpt}{$ENDIF}
function CRCInit(var CRCDef: TCRCDef; CRCType: TCRCType): Boolean;
type
  PCRCTab = ^TCRCTab;
  TCRCTab = array[TCRCType] of packed record
    Poly, Bits, Init, FInit: Cardinal;
    Inverse: LongBool;
  end;

const
  CRCTab: array[0..5*10-1] of Cardinal = (
    //    Polynom   Bits InitVec    FinitVec   Inverse
          $000000D1,  8, $00000000, $00000000, Cardinal(-1),   // CRC_8  GSM/ERR
          $00000233, 10, $00000000, $00000000, Cardinal(-1),   // CRC_10 ATM/OAM Cell
          $0000080F, 12, $00000000, $00000000, Cardinal(-1),   // CRC_12
          $00008005, 16, $00000000, $00000000, Cardinal(-1),   // CRC_16 ARC,IBM
          $00001021, 16, $00001D0F, $00000000, Cardinal(0),    // CRC_16 CCITT ITU
          $00008408, 16, $00000000, $00000000, Cardinal(-1),   // CRC_16 XModem
          $00864CFB, 24, $00B704CE, $00000000, Cardinal(0),    // CRC_24
          $9DB11213, 32, $FFFFFFFF, $FFFFFFFF, Cardinal(-1),   // CRC_32
          $04C11DB7, 32, $FFFFFFFF, $FFFFFFFF, Cardinal(-1),   // CRC_32CCITT
          $04C11DB7, 32, $FFFFFFFF, $00000000, Cardinal(-1)    // CRC_32ZModem
    );

    // some other CRC's, not all yet verfied
    // DD    $00000007,  8, $00000000, $00000000, -1   // CRC_8  ATM/HEC
    // DD    $00000007,  8, $00000000, $00000000,  0   // CRC_8 the SMBus Working Group
    // DD    $00004599, 15, $00000000, $00000000, -1   // CRC_15 CANBus
    // DD    $00001021, 16, $00000000, $00000000,  0   // CRC_16ZModem
    // DD    $00001021, 16, $0000FFFF, $00000000,  0   // CRC_16 CCITT British Aerospace
    // DD    $00004003, 16, $00000000, $00000000, -1   // CRC_16 reversed
    // DD    $00001005, 16, $00000000, $00000000, -1   // CRC_16 X25
    // DD    $00000053, 16, $00000000, $00000000, -1   // BasicCard 16Bit CRC (sparse poly for Crypto MCU)
    // DD    $000000C5, 32, $00000000, $00000000, -1   // BasicCard 32Bit CRC

begin
  with PCRCTab(@CRCTab)[CRCType] do
    Result := CRCSetup(CRCDef, Poly, Bits, Init, FInit, Inverse);
end;
{$IFDEF NoOpt}{$O-}{$ENDIF}

function CRCDone(var CRCDef: TCRCDef): Cardinal; {$IFDEF UseASM86}register;{$ENDIF}
{$IFDEF UseASM86}
asm // finalize CRCDef after a computation
       MOV   EDX,[EAX].TCRCDef.CRC
       MOV   ECX,[EAX].TCRCDef.InitVector
       XOR   EDX,[EAX].TCRCDef.FinalVector
       MOV   [EAX].TCRCDef.CRC,ECX
       AND   EDX,[EAX].TCRCDef.Mask
       MOV   EAX,EDX
end;
{$ELSE}
begin
  Result := CRCDef.CRC xor CRCDef.FinalVector;
  CRCDef.CRC := CRCDef.InitVector;
  Result := Result and CRCDef.Mask;
end;
{$ENDIF}

function CRCCalc(CRCType: TCRCType; const Buffer; Size: Cardinal): Cardinal;
// inplace calculation
var
  CRC: TCRCDef;
begin
  {$HINTS OFF}
  CRCInit(CRC, CRCType);
  {$HINTS ON}
  Result := CRCCode(CRC, Buffer, Size);
end;

function CRCCalcEx(CRCType: TCRCType; ReadMethod: TReadMethod; Size: Cardinal): Cardinal;
var
  CRC: TCRCDef;
begin
  {$HINTS OFF}
  CRCInit(CRC, CRCType);
  {$HINTS ON}
  Result := CRCCodeEx(CRC, ReadMethod, Size);
end;

// predefined CRC16/CRC32CCITT, avoid slower lookuptable computation by use of precomputation 
var
  FCRC16: PCRCDef = nil;
  FCRC32: PCRCDef = nil;

function CRC16Init: Pointer;
begin
  GetMem(FCRC16, SizeOf(TCRCDef));
  CRCInit(FCRC16^, CRC_16);
  Result := FCRC16;
end;

function CRC16(CRC: Word; const Buffer; Size: Cardinal): Word;
{$IFDEF UseASM86}
asm
       JECXZ @@2
       PUSH  EDI
       PUSH  ESI
       MOV   EDI,ECX
{$IFDEF PIC}
       MOV   ESI,[EBX].FCRC16
{$ELSE}
       MOV   ESI,FCRC16
{$ENDIF}
       XOR   ECX,ECX
       TEST  ESI,ESI
       JZ    @@3
@@1:   MOV    CL,[EDX]
       XOR    CL,AL
       SHR   EAX,8
       INC   EDX
       XOR   EAX,[ESI + ECX * 4]
       DEC   EDI
       JNZ   @@1
       POP   ESI
       POP   EDI
@@2:   RET
@@3:   PUSH  EAX
       PUSH  EDX
       CALL  CRC16Init
       MOV   ESI,EAX
       XOR   ECX,ECX
       POP   EDX
       POP   EAX
       JMP   @@1
end;
{$ELSE}
var
  T: PCRCDef;
  B: PByte;
begin
  Result := CRC;
  if Size > 0 then
  begin
    T := FCRC16;
    if T = nil then
      T := CRC16Init;

    B := PByte(@Buffer);
    repeat
      Result := T^.Table[B^ xor Byte(Result)] xor (Result shr 8);
      Inc(B);
      Dec(Size);
    until Size = 0;
  end;
end;
{$ENDIF}

function CRC32Init: Pointer;
begin
  GetMem(FCRC32, SizeOf(TCRCDef));
  CRCInit(FCRC32^, CRC_32CCITT);
  Result := FCRC32;
end;

function CRC32(CRC: Cardinal; const Buffer; Size: Cardinal): Cardinal;
{$IFDEF UseASM86}
asm
       JECXZ @@2
       PUSH  EDI
       PUSH  ESI
       NOT   EAX                    // inverse Input CRC
       MOV   EDI,ECX
{$IFDEF PIC}
       MOV   ESI,[EBX].FCRC32
{$ELSE}
       MOV   ESI,FCRC32
{$ENDIF}
       XOR   ECX,ECX
       TEST  ESI,ESI
       JZ    @@3
@@1:   MOV    CL,[EDX]
       XOR    CL,AL
       SHR   EAX,8
       INC   EDX
       XOR   EAX,[ESI + ECX * 4]
       DEC   EDI
       JNZ   @@1
       NOT   EAX                    // inverse Output CRC
       POP   ESI
       POP   EDI
@@2:   RET
@@3:   PUSH  EAX
       PUSH  EDX
       CALL  CRC32Init
       MOV   ESI,EAX
       XOR   ECX,ECX
       POP   EDX
       POP   EAX
       JMP   @@1
end;
{$ELSE}
var
  T: PCRCDef;
  B: PByte;
begin
  if Size > 0 then
  begin
    Result := not CRC;
    T := FCRC32;
    if T = nil then
      T := CRC32Init;

    B := PByte(@Buffer);
    repeat
      Result := T^.Table[B^ xor Byte(Result)] xor (Result shr 8);
      Inc(B);
      Dec(Size);
    until Size = 0;

    Result := not Result;
  end
  else
    Result := CRC;
end;
{$ENDIF}

procedure CRCInitThreadSafe;
begin
  CRC16Init;
  CRC32Init;
end;

initialization

finalization
  if FCRC16 <> nil then FreeMem(FCRC16);
  if FCRC32 <> nil then FreeMem(FCRC32);
  
end.
