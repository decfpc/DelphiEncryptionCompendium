program DECTest;

{$IFDEF FPC}
  {$MODE Delphi}
  {$IFDEF MSWINDOWS}
    {$APPTYPE console}
  {$ENDIF}
{$ENDIF}

uses
  Classes,
  {$IFDEF MSWINDOWS}
  DECCPU,
  windows,
  {$ENDIF}
  {$IFDEF FPC}
  EpikTimer,
  {$ENDIF}
  SysUtils,
  TypInfo,
  DECCRC,
  DECUtil,
  DECFmt,
  DECHash,
  DECCipher,
  DECRandom,
  Variants; // Variants required for SetPropValue in FPC (else access violation when converting AnsiString to Variant)

{$R *.res}

procedure RegisterClasses;
begin
  RegisterDECClasses([TFormat_HEX, TFormat_HEXL, TFormat_MIME32, TFormat_MIME64,
                      TFormat_PGP, TFormat_UU, TFormat_XX, TFormat_ESCAPE]);

// preferred hashes
  THash_MD2.Register;        // 1.5Kb
  THash_MD4.Register;        // 2.0Kb                           // for fast checksums
  THash_MD5.Register;        // 2.5Kb
  THash_SHA.Register;        // 10Kb for SHA,SHA1,SHA256        // strong
  THash_SHA1.Register;
  THash_SHA256.Register;
  THash_SHA384.Register;     // 3.0Kb for SHA384,SHA512
  THash_SHA512.Register;                                        // variable digest
  THash_Sapphire.Register;   // 1.0Kb

  THash_Panama.Register;     // 2.0Kb
  THash_Tiger.Register;      // 12.0kb
  THash_RipeMD128.Register;  // 4.0Kb
  THash_RipeMD160.Register;  // 8.0Kb
  THash_RipeMD256.Register;  // 4.5Kb
  THash_RipeMD320.Register;  // 9.0Kb
  THash_Haval128.Register;   // 6.0Kb for all Haval's
  THash_Haval160.Register;
  THash_Haval192.Register;
  THash_Haval224.Register;
  THash_Haval256.Register;
  THash_Whirlpool.Register;   // 10.0Kb
  THash_Whirlpool1.Register;  // 10.0Kb
  THash_Square.Register;      // 10Kb
  THash_Snefru128.Register;   // 18Kb
  THash_Snefru256.Register;   //

//  TCipher_Null.Register;
  TCipher_Blowfish.Register;
  TCipher_Twofish.Register;
  TCipher_IDEA.Register;
  TCipher_CAST256.Register;
  TCipher_Mars.Register;
  TCipher_RC4.Register;
  TCipher_RC6.Register;
  TCipher_Rijndael.Register;
  TCipher_Square.Register;
  TCipher_SCOP.Register;
  TCipher_Sapphire.Register;
  TCipher_1DES.Register;
  TCipher_2DES.Register;
  TCipher_3DES.Register;
  TCipher_2DDES.Register;
  TCipher_3DDES.Register;
  TCipher_3TDES.Register;
  TCipher_3Way.Register;
  TCipher_Cast128.Register;
  TCipher_Gost.Register;
  TCipher_Misty.Register;
  TCipher_NewDES.Register;
  TCipher_Q128.Register;
  TCipher_RC2.Register;
  TCipher_RC5.Register;
  TCipher_SAFER.Register;
  TCipher_Shark.Register;
  TCipher_Skipjack.Register;
  TCipher_TEA.Register;
  TCipher_TEAN.Register;
end;

function DoEnumClasses(Data: Pointer; const ClassType: TDECClass): Boolean;
begin
  Result := False;
  WriteLn(IntToHEX(ClassType.Identity, 8), ' : ', ClassType.ClassName);
end;

procedure PrintRegisteredClasses;
begin
  WriteLn('registered classes');
  WriteLn;
  DECEnumClasses(@DoEnumClasses, nil);
  WriteLn;
end;

type
  TTestProc = procedure of object;

  // process testcases in file DECTest.vec
  TTestRunner = class
  private
    FVectorFile: Text;
    FCurChar: PAnsiChar;
    FLineNo: Integer;
    FInstance: TObject;
    FClassType: TDECClass;
    // Cipher only special properties
    FPassword: Binary;
    FIV: Binary;
    FIFiller: Byte;

    procedure InvalidLine;
    function ExtractClassName: PAnsiChar;
    procedure ExtractProperty(Instance: TObject);
    function ExtractTestResult: Binary;
    function ExtractTest(out Data: Binary; out Count: Integer): Boolean;
    procedure TestHash;
    procedure TestCipher;
    procedure TestFormat;
  public
    constructor Create(const AFileName: string);
    destructor Destroy; override;

    procedure Run;
  end;

procedure TTestRunner.InvalidLine;
begin
  raise Exception.CreateFmt('Invalid line format at %d', [FLineNo]);
end;

function TTestRunner.ExtractClassName: PAnsiChar;
begin
  while FCurChar^ in [' ', '['] do Inc(FCurChar);
  Result := FCurChar;
  while FCurChar^ <> #0 do Inc(FCurChar);
  while FCurChar^ in [#0, ']', ' ', #13, #10] do Dec(FCurChar);
  FCurChar[1] := #0;
end;

procedure TTestRunner.ExtractProperty(Instance: TObject);
// setup property stored in Testvectors
// format is .PropName=PropValue
var
  PropName: PAnsiChar;
begin
  while FCurChar^ in [' ', '.'] do Inc(FCurChar);
  PropName := FCurChar;
  while not (FCurChar^ in [#0, '=']) do Inc(FCurChar);
  if FCurChar^ <> #0 then
  begin
    FCurChar^ := #0;
    Inc(FCurChar);
    while FCurChar^ in ['=', ' '] do Inc(FCurChar);
    if Instance is TDECCipher then
      if AnsiCompareText(PropName, 'Password') = 0 then
      begin
        FPassword := TFormat_Escape.Decode(FCurChar^, StrLen(FCurChar));
        with TDECCipher(Instance).Context do
          if Length(FPassword) > KeySize then SetLength(FPassword, KeySize);
        Exit;
      end else
        if AnsiCompareText(PropName, 'IV') = 0 then
        begin
          FIV := TFormat_Escape.Decode(FCurChar^, StrLen(FCurChar));
          Exit;
        end else
          if AnsiCompareText(PropName, 'IFiller') = 0 then
          begin
            FIFiller := StrToInt(FCurChar);
            Exit;
          end;
    try
      SetPropValue(Instance, PropName, AnsiString(FCurChar));
    except
      on E: Exception do
      begin
        E.Message := E.Message + ' on ' + Instance.ClassName;
        raise;
      end;
    end;
  end else InvalidLine;
end;

function TTestRunner.ExtractTestResult: Binary;
// extract valid test result, and convertion from Escaped string
// repositionate to testcases
var
  R,P: PAnsiChar;
begin
  while FCurChar^ in [' ', '<'] do Inc(FCurChar);
  R := FCurChar;
  while not (FCurChar^ in [#0, '>']) do Inc(FCurChar);
  if FCurChar^ <> '>' then InvalidLine;
  P := FCurChar;
  while P^ in ['>', ' '] do Inc(P);
  if P^ <> '=' then InvalidLine;
  FCurChar^ := #0;
  while P^ in ['=', ' ', '>'] do Inc(P);
  FCurChar := P;
  Result := TFormat_Escape.Decode(R^, StrLen(R));
end;

function TTestRunner.ExtractTest(out Data: Binary; out Count: Integer): Boolean;
// extract one testcase and repetition
var
  L: Boolean;
  T: Binary;
begin
  Result := FCurChar^ <> #0;
  if Result then
  begin
    Count := 0;
    Data := '';
    while FCurChar^ = ' ' do Inc(FCurChar);
    while FCurChar^ in ['0'..'9'] do
    begin
      Count := Count * 10 + Ord(FCurChar^) - Ord('0');
      Inc(FCurChar);
    end;
    L := FCurChar^ = '!';
    while not (FCurChar^ in [#0, '<']) do Inc(FCurChar);
    if FCurChar^ = '<' then
    begin
      Inc(FCurChar);
      while not (FCurChar^ in [#0, '>']) do
      begin
        Data := Data + FCurChar^;
        Inc(FCurChar);
      end;
      if FCurChar^ <> '>' then InvalidLine;
    end else InvalidLine;
    while FCurChar^ in ['>',','] do Inc(FCurChar);
    Data := TFormat_Escape.Decode(Data);
    if L then
    begin
      T := '';
      repeat
        T := T + Data;
        Dec(Count);
      until Count <= 0;
      Count := 1;
      Data := T;
    end;
  end;
end;

procedure TTestRunner.TestHash;
// apply testcases to hash function
var
  Digest: Binary;
  Data: Binary;
  Count: Integer;
  Hash: TDECHash;
begin
  Hash := TDECHash(FInstance);
  Digest := ExtractTestResult;
  Hash.Init;
  while ExtractTest(Data, Count) do
    repeat
      Hash.Calc(Data[1], Length(Data));
      Dec(Count);
    until Count <= 0;
  Hash.Done;

  Write(FLineNo:5, ': ', Hash.Classname, ' ');
  if AnsiCompareText(Hash.DigestStr(TFormat_HEXL), Digest) <> 0 then WriteLn(Digest, ' != ', Hash.DigestStr(TFormat_HEXL))
    else WriteLn('test ok.');
end;

procedure TTestRunner.TestCipher;
var
  CipherText,PlainText,TestResult,PlainResult: Binary;
  Cipher: TDECCipher;
  Count: Integer;
begin
  Cipher := TDECCipher(FInstance);
  CipherText := ExtractTestResult;
  Cipher.Init(FPassword, FIV, FIFiller);
  TestResult := '';
  PlainResult := '';
  while ExtractTest(PlainText, Count) do
  begin
    PlainResult := PlainResult + PlainText;
    TestResult := TestResult + Cipher.EncodeBinary(PlainText, TFormat_Copy);
    Dec(Count);
  end;
  Cipher.Done;
  TestResult := TFormat_HEXL.Encode(TestResult);

  Write(FLineNo:5, ': ', Cipher.Classname, ' ');
  if CipherText <> TestResult then
  begin
    WriteLn(CipherText, ' != ', TestResult);
    Exit;
  end;
  TestResult := Cipher.DecodeBinary(TestResult, TFormat_HEXL);
  if TestResult <> PlainResult then
  begin
    WriteLn('decode error');
    Exit;
  end;
  WriteLn('test ok.');
end;

procedure TTestRunner.TestFormat;
// apply testcases to conversions function
var
  Test,Output,Data: Binary;
  Count: Integer;
  Format: TDECFormatClass;
begin
  Format := TDECFormatClass(FClassType);
  Test := ExtractTestResult;
  ExtractTest(Data, Count);
  Output := Format.Encode(Data);

  Write(FLineNo:5, ': ', Format.Classname, ' ');
  if Test <> Output then
    WriteLn(Test, ' != ', Output)
  else if Format.Decode(Output) <> Data then
    Writeln('Decode FAILED: ', Format.Decode(Output), ' != ', Data)
  else
    WriteLn('test ok.');
end;

constructor TTestRunner.Create(const AFileName: string);
begin
  Assign(FVectorFile, AFileName);
end;

destructor TTestRunner.Destroy;
begin
  Close(FVectorFile);
  FreeAndNil(FInstance);
end;

procedure TTestRunner.Run;
var
  Line: AnsiString;
  TestProc: TTestProc;
begin
  WriteLn('processing test cases');
  WriteLn;

  TestProc := nil;
  Reset(FVectorFile);
  while not EOF(FVectorFile) do
  begin
    ReadLn(FVectorFile, Line);
    FCurChar := PAnsiChar(Line);
    while (FCurChar^ <> #0) and (FCurChar^ = ' ') do Inc(FCurChar);
    Inc(FLineNo);
    case FCurChar^ of
       #0: ;
      '#': ; // remark
      '[': begin // class
             FreeAndNil(FInstance);
             TestProc := nil;
             FClassType := nil;
             if FCurChar[1] <> '#' then
             try
               FClassType := DECClassByName(ExtractClassName, TDECObject);
               if FClassType.InheritsFrom(TDECHash) then
               begin
                 FInstance := FClassType.Create;
                 TestProc := TestHash;
               end else
                 if FClassType.InheritsFrom(TDECFormat) then
                 begin
                   TestProc := TestFormat;
                 end else
                   if FClassType.InheritsFrom(TDECCipher) then
                   begin
                     FPassword := '';
                     FIV := '';
                     FIFiller := $FF;
                     FInstance := FClassType.Create;
                     TestProc := TestCipher;
                   end;
             except
               on E: Exception do
               begin
                 WriteLn(E.Message);
               end;
             end;
           end;
      '.': if FInstance <> nil then
             ExtractProperty(FInstance);
      '<': if Assigned(TestProc) then // testcase
           begin
             TestProc;
           end;
    else
      if FClassType <> nil then
        InvalidLine;
    end;
  end;

  WriteLn;
end;

const
  HashBufferSize = 1024 * 16;

{$IFDEF MSWINDOWS}
function DoSpeedHash(Buffer: PByteArray; HashClass: TDECHashClass): Boolean;
var
  Start,Stop: Int64;
  ThreadPriority: Cardinal;
  ProcessPriority: Cardinal;
  I: Integer;
begin
  Result := False;
  ProcessPriority := GetPriorityClass(GetCurrentProcess);
  ThreadPriority := GetThreadPriority(GetCurrentThread);
  with HashClass.Create do
  try
    SetPriorityClass(GetCurrentProcess, REALTIME_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread, THREAD_PRIORITY_TIME_CRITICAL);
    Sleep(0);
    Start := DECCPU.RDTSC;
    for I := 0 to 4 do
    begin
      Init;
      Calc(Buffer[0], HashBufferSize);
      Done;
    end;
    Stop := (DECCPU.RDTSC - Start) div 5;
    WriteLn(ClassName, StringOfChar(' ', 20 - Length(ClassName)), ': ',
            Stop/HashBufferSize:10:1, ' cycles/byte ',
            CPUSpeed/Stop*HashBufferSize:10:2, ' Mb/sec');
  finally
    Free;
    SetThreadPriority(GetCurrentThread, ThreadPriority);
    SetPriorityClass(GetCurrentProcess, ProcessPriority);
  end;
  Sleep(0);
end;
{$ELSE}
function DoSpeedHash(Buffer: PByteArray; HashClass: TDECHashClass): Boolean;
var
  Timer: TEpikTimer;
  I: Integer;
begin
  Result := False;
  Timer := TEpikTimer.Create(nil);
  with HashClass.Create do
  try
    Timer.Start;
    for I := 0 to 15 do
    begin
      Init;
      Calc(Buffer[0], HashBufferSize);
      Done;
    end;
    Timer.Stop;
    WriteLn(ClassName, StringOfChar(' ', 20 - Length(ClassName)), ': ',
            (1/Timer.Elapsed/4):10:2, ' Mb/sec');
  finally
    Free;
    Timer.Free;
  end;
end;
{$ENDIF}

procedure SpeedTestHashs;
var
  Buffer: Binary;
begin
  WriteLn('compute hash performances');
  WriteLn;
  Buffer := '';
  SetLength(Buffer, HashBufferSize);
  RandomBuffer(Buffer[1], HashBufferSize);
  DECEnumClasses(@DoSpeedHash, Pointer(Buffer), TDECHash);
  WriteLn;
end;

const
  TEST_VECTOR: array[0..39] of Byte = (
    $30, $44, $ED, $6E, $45, $A4, $96, $F5,
    $F6, $35, $A2, $EB, $3D, $1A, $5D, $D6,
    $CB, $1D, $09, $82, $2D, $BD, $F5, $60,
    $C2, $B8, $58, $A1, $91, $F9, $81, $B1,
    $00, $00, $00, $00, $00, $00, $00, $00
  );

function DoTestCipher(Dummy: Pointer; CipherClass: TDECCipherClass): Boolean;
var
  Buffer: array[0..31] of Byte;
  Key: Binary;
  I: Integer;
begin
  Result := False;
  Key := CipherClass.ClassName;
  I := Length(Key);
  with CipherClass.Context do
    if I > KeySize then I := KeySize;
  SetLength(Key, I);

  with CipherClass.Create do
  try
    Mode := cmCTSx;
    Init(Key);

    Encode(TEST_VECTOR, Buffer, SizeOf(Buffer));
    Done;

    Decode(Buffer, Buffer, SizeOf(Buffer));
    Done;
    if not CompareMem(@TEST_VECTOR, @Buffer, SizeOf(Buffer)) then
      WriteLn(ClassName + StringOfChar(' ', 18 - Length(ClassName)), 'selftest fails');
  finally
    Free;
  end;
end;

procedure TestCipher;
begin
  DECEnumClasses(@DoTestCipher, nil, TDECCipher);
end;

const
  CipherBufferSize = 1024 * 16 * 2;

{$IFDEF MSWINDOWS}
function DoSpeedCipher(Buffer: PByteArray; CipherClass: TDECCipherClass): Boolean;
var
  Start,Stop: Int64;
  ThreadPriority: Cardinal;
  ProcessPriority: Cardinal;
  I,S: Integer;
begin
  Result := False;
  ProcessPriority := GetPriorityClass(GetCurrentProcess);
  ThreadPriority := GetThreadPriority(GetCurrentThread);
  with CipherClass.Create do
  try
    Mode := cmECBx;
    Init(StringOfChar('x', Context.KeySize));

    S := CipherBufferSize shr 1;
    I := S mod Context.BufferSize;
    Dec(S, I);

    SetPriorityClass(GetCurrentProcess, REALTIME_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread, THREAD_PRIORITY_TIME_CRITICAL);
    Sleep(0);
    Start := DECCPU.RDTSC;
    for I := 0 to 2 do
    begin
      Encode(Buffer[0], Buffer[S], S);
      Done;
      Decode(Buffer[0], Buffer[S], S);
      Done;
    end;
    Stop := (DECCPU.RDTSC - Start) div 6;
    WriteLn(ClassName, StringOfChar(' ', 20 - Length(ClassName)), ': ',
            Stop/S:10:1, ' cycles/byte ',
            CPUSpeed/Stop*S:10:2, ' Mb/sec');
  finally
    Free;
    SetThreadPriority(GetCurrentThread, ThreadPriority);
    SetPriorityClass(GetCurrentProcess, ProcessPriority);
  end;
  Sleep(0);
end;
{$ELSE}
function DoSpeedCipher(Buffer: PByteArray; CipherClass: TDECCipherClass): Boolean;
var
  Timer: TEpikTimer;
  I, S: Integer;
begin
  Result := False;
  Timer := TEpikTimer.Create(nil);
  with CipherClass.Create do
  try
    Mode := cmECBx;
    Init(StringOfChar('x', Context.KeySize));

    S := CipherBufferSize shr 1;
    I := S mod Context.BufferSize;
    Dec(S, I);
    Timer.Start;
    for I := 0 to 7 do
    begin
      Encode(Buffer[0], Buffer[S], S);
      Done;
      Decode(Buffer[0], Buffer[S], S);
      Done;
    end;
    Timer.Stop;
    WriteLn(ClassName, StringOfChar(' ', 20 - Length(ClassName)), ': ',
            (1/Timer.Elapsed/4):10:2, ' Mb/sec');
  finally
    Free;
    Timer.Free;
  end;
end;
{$ENDIF}

procedure SpeedTestCiphers;
var
  Buffer: Binary;
begin
  WriteLn('compute cipher performances');
  WriteLn;
  Buffer := '';
  SetLength(Buffer, CipherBufferSize);
  RandomBuffer(Buffer[1], CipherBufferSize);
  DECEnumClasses(@DoSpeedCipher, Pointer(Buffer), TDECCipher);
  WriteLn;
end;

procedure DemoCipher(Index: Integer);
// demonstrate en/decryption with cipher Blowfish and use of a
// secure Hash based random KDF -> Key Derivation Function
var
  Seed, Encoded, Decoded: Binary;
begin
  Seed := RandomBinary(16);

  with TCipher_Blowfish.Create do
  try
    Init(THash_SHA1.KDFx('Password here', Seed, Context.KeySize));
    Encoded := EncodeBinary('Secret data here', TFormat_MIME64);
  finally
    Free;
  end;

  with TCipher_Blowfish.Create do
  try
    Init(THash_SHA1.KDFx('Password here', Seed, Context.KeySize));
    Decoded := DecodeBinary(Encoded, TFormat_MIME64);
  finally
    Free;
  end;

  WriteLn(#13#10'Demo Cipher #', Index);
  WriteLn('encoded: ', Encoded);
  WriteLn('decoded: ', Decoded);
end;

procedure DemoCipherFile;
// demonstrates a "very" secure application of ciphers, hashes, key derivation functions and random seeds.


  procedure EncodeFile(const AFileName: String; const APassword: Binary;
                       ACipher: TDECCipherClass = nil; AMode: TCipherMode = cmCTSx;
                       AHash: TDECHashClass = nil);
  // The source file will be encrypted, then completely overwritten and deleted.
  // The file will be encrypted with a session key that was generated with
  // a KDF (Key Derivation Function) and a random number.
  // The random number == seed has a size of 128 bits and is stored in the encrypted file.
  // It ensured that it will be impossible to crack the password and at the same time it
  // randomizes the encryption output. A checksum that was generated using CMAC
  // (Cipher Message Authentication Code) is stored at the end of the file.
  // Furthermore the encrypted file contains a header with information about the used
  // Cipher-/Hash algorithm, CipherMode etc. This makes it possible to automatically
  // select the correct algorithms for decrypting the file (as long as one has the password).
  // If nil is passed for ACipher and/or AHash, then a default cipher/hash will be used.
  // The used session key always has random properties, it's practically random data.
  // Only those who know the random seed and APassword are able to decrypt the data.
  var
    Dest: TStream;

    procedure Write(const Value; Size: Integer);
    begin
      Dest.WriteBuffer(Value, Size);
    end;

    procedure WriteByte(Value: Byte);
    begin
      Write(Value, SizeOf(Value));
    end;

    procedure WriteLong(Value: LongWord);
    begin
      Value := SwapLong(Value);
      Write(Value, SizeOf(Value));
    end;

    procedure WriteBinary(const Value: Binary);
    begin
      WriteByte(Length(Value));
      Write(Value[1], Length(Value));
    end;

  var
    Source: TStream;
    Seed: Binary;
  begin
    ACipher := ValidCipher(ACipher);
    AHash := ValidHash(AHash);

    Seed := RandomBinary(16);

    Source := TFileStream.Create(AFileName, fmOpenReadWrite);
    try
      Dest := TFileStream.Create(AFileName + '.enc', fmCreate);
      try
        with ACipher.Create do
        try
          Mode := AMode;
          Init(AHash.KDFx(APassword, Seed, Context.KeySize));

          WriteLong(Identity);
          WriteByte(Byte(Mode));
          WriteLong(AHash.Identity);
          WriteBinary(Seed);
          WriteLong(Source.Size);
          EncodeStream(Source, Dest, Source.Size);
          WriteBinary(CalcMAC);
        finally
          Free;
        end;
      finally
        Dest.Free;
      end;
      ProtectStream(Source);
    finally
      Source.Free;
    end;
    DeleteFile(AFileName);
  end;

  procedure DecodeFile(const AFileName: String; const APassword: Binary);
  // Decrypt a file previously encrypted with EncodeFile().
  var
    Source: TStream;

    procedure Read(var Value; Size: Integer);
    begin
      Source.ReadBuffer(Value, Size);
    end;

    function ReadByte: Byte;
    begin
      Read(Result, SizeOf(Result));
    end;

    function ReadLong: LongWord;
    begin
      Read(Result, SizeOf(Result));
      Result := SwapLong(Result);
    end;

    function ReadBinary: Binary;
    begin
      SetLength(Result, ReadByte);
      Read(Result[1], Length(Result));
    end;

  var
    Dest: TStream;
  begin
    Source := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyNone);
    try
      try
        Dest := TFileStream.Create(ChangeFileExt(AFileName, ''), fmCreate);
        try
          try
            with CipherByIdentity(ReadLong).Create do
            try
              Mode := TCipherMode(ReadByte);
              Init(HashByIdentity(ReadLong).KDFx(APassword, ReadBinary, Context.KeySize));
              DecodeStream(Source, Dest, ReadLong);
              if ReadBinary <> CalcMAC then
                raise EDECException.Create('Invalid decryption');
            finally
              Free;
            end;
          except
            ProtectStream(Dest);
            raise;
          end;
        finally
          Dest.Free;
        end;
      except
        DeleteFile(ChangeFileExt(AFileName, ''));
        raise;
      end;
    finally
      Source.Free;
    end;
  end;

var
  FileName: String;
begin
  WriteLn(#13#10'File En/Decryption test');

  FileName := ChangeFileExt(ParamStr(0), '.test');
  if not FileExists(FileName) then
  begin
    Writeln('Skipped (', FileName, ' does not exist)');
    Exit;
  end;

  SetDefaultCipherClass(TCipher_Rijndael);
  SetDefaultHashClass(THash_SHA1);
  // Set the base identity for the cipher/hash algorithms to an application specific value.
  // This ensures that only files that were encrypted with this application can be decrypted.
  // The identity of the used cipher/hash is stored in the file by EncodeFile().
  // When decrypting with DecodeFile(), the identities will be read and the respective
  // DECClasses will be loaded.
  IdentityBase := $84485225;
  // When using the identity concept, all used ciphers/hashes need to be registered.
  RegisterDECClasses([TCipher_Rijndael, THash_SHA1]);
  // The lines above should usually be executed during application startup.

  EncodeFile(FileName, 'Password');
  DecodeFile(FileName + '.enc', 'Password');
end;

begin
  RandomSeed; // randomize DEC's own RNG
  // Uncomment these two lines if the program output should be written to a text file instead of stdout
  //AssignFile(Output, ChangeFileExt(ParamStr(0), '.txt'));
  //Rewrite(Output);
  try
    RegisterClasses;
    PrintRegisteredClasses;
    with TTestRunner.Create(ExtractFilePath(ParamStr(0)) + 'DECTest.vec') do
    begin
      try
        Run;
      finally
        Free;
      end;
    end;
    {$IF DEFINED(MSWINDOWS) OR DEFINED(FPC)}
    SpeedTestHashs;
    {$IFEND}
    TestCipher;
    {$IF DEFINED(MSWINDOWS) OR DEFINED(FPC)}
    SpeedTestCiphers;
    {$IFEND}

    DemoCipher(0);
    DemoCipher(1);
    DemoCipher(2);

    DemoCipherFile;
  except
    on E: Exception do
      WriteLn(E.Message);
  end;
  {$IFDEF MSWINDOWS}
  Readln;
  {$ENDIF}
end.

