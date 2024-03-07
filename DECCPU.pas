{*****************************************************************************

  Delphi Encryption Compendium (DEC)
  Version 5.3 for Delphi 7 - 10.4 or higher/FPC 2.6 or higher

  Remarks:          Public Domain, Copyright must be included

  Original Author:  (c) 2006 Hagen Reddmann, HaReddmann [at] T-Online [dot] de
  Modifications:    (c) 2008 Arvid Winkelsdorf, info [at] digivendo [dot] de
                    (c) 2017, 2021 decfpc

  Description:      CPU Detection, standalone unit. Windows only.

  Remarks:
  - codesizes       503 (CPUType)
                   1003 (CPUType, CPUSpeed)
                   5035 (CPUType, CPUSpeed, CPUVendor) bytes
  - datasize (BSS)  142 bytes
  - datasize (DATA) 100 bytes if CPUVendor is used
    minimal         645 bytes in EXE

*****************************************************************************}

unit CPU;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

{$IFDEF MSWINDOWS}
type
  {CPU Detection}
  TCPUData = packed record
    Typ: Byte;
    Family: Byte;
    Model: Byte;
    Stepping: Byte;
    Signature: Cardinal;            // encoded Typ/Family/Model/Stepping
    Features_EDX: Cardinal;         // Features
    Features_EBX: Cardinal;
    Features_ECX: Cardinal;
    FeaturesEx_EDX: Cardinal;       // extended Features AMD/Cyrix
    FeaturesEx_EBX: Cardinal;
    FeaturesEx_ECX: Cardinal;
    Vendor: array[0..12] of AnsiChar;   // inculdes trailing #0
    VendorEx: array[0..64] of AnsiChar; //    "         "
    CPUID3: array[0..4] of Cardinal;
    VendorID: Cardinal;
    TLB_EAX: Cardinal;              // Cache and TLB Infos, see Intel Docus
    TLB_EDX: Cardinal;
    TLB_EBX: Cardinal;
    TLB_ECX: Cardinal;
  end;

const
  // CPU Family codes
  cf386        = 3;
  cf486        = 4;
  cfPentium    = 5;
  cfPentiumPro = 6;
  // CPU Types
  ctOEM        = 0;
  ctOverdrive  = 1;
  ctDual       = 2;
  // Vendor codes
  cvIntel      = $506E7F40; // CRC('GenuineIntel'); Intel
  cvAMD        = $454D5A47; // CRC('AuthenticAMD'); AMD
  cvCyrix      = $7E7D554F; // CRC('CyrixInstead'); Cyrix
  cvUMC        = $20434D55; // CRC('UMC UMC UMC '); UMC
  cvNexGen     = $5B597D42; // CRC('NexGenDriven'); NexGen
  cvCentaur    = $4F706543; // CRC('CentaurHauls'); Centaur/IDT
  cvRise       = $65736952; // CRC('RiseRiseRise'); Rise Technology
  cvTransmeta  = $17337363; // CRC('GenuineTMx86'); Transmeta

  // CPU Features
  ffFPU        = $00000001; // Floating Point Unit on Chip
  ffVME        = $00000002; // Virtual 8086 Mode Enhancements
  ffDE         = $00000004; // Debugging Extensions
  ffPSE        = $00000008; // Page Size Extensions
  ffTSC        = $00000010; // Time Stamp Counter, supports RDTSC Instruction
  ffMSR        = $00000020; // Model Specific Registers, supports RDMSR Instruction
  ffPAE        = $00000040; // Physical Address Extension
  ffMCE        = $00000080; // Machine Check Exception
  ffCX8        = $00000100; // CMPXCHG Instruction supported
  ffAPIC       = $00000200; // Advanced Programmable Interrupt Controller
  // ffRes1       = $00000400;
  ffSEP        = $00000800; // Fast System Call, SYSENTER and SYSEXIT Instruction
  ffMTRR       = $00001000; // Memory Type Range Registers
  ffPGE        = $00002000; // Global Flag Processor supported
  ffMCA        = $00004000; // Machine Check Architecture
  ffCMOV       = $00008000; // CMOV/FCOMI Instructions supported
  ffFGPAT      = $00010000; // Page Attribute Table, CMOVcc supported
  ffPSE36      = $00020000; // PSE-36—36-bit Page Size Extension
  ffPN         = $00040000; // PN—Processor Number, supports the 96-bit PN feature
  ffCLFSH      = $00080000; // CLFLUSH intsturction supported
  // ffRes2       = $00100000;
  ffDS         = $00200000; // Debug Store supported
  ffACPI       = $00400000; // Thermal Monitor and Software Controlled Clock Features
  ffMMX        = $00800000; // MMX instruction set
  ffFXSR       = $01000000; // Fast FP/MMX™ Technology/Streaming SIMD Extensions
  ffSSE        = $02000000; // Streaming SIMD Extensions Instruction set
  ffSSE2       = $04000000; // Streaming SIMD Extensions Instruction set 2
  ffSS         = $08000000; // Self-Snoop supported
  ffHTT        = $10000000; // Hyper-Threading Technology 
  ffTM         = $20000000; // Thermal control circuit TCC supported
  ffIA64       = $40000000; // IA-64 architecture
  // ffRes5       = $80000000;

type
  CPUDouble = {$IFDEF CPU386}Comp{$ELSE}Double{$ENDIF};

function CPUType: Integer; {any cfXXXX Value}
function CPUData: TCPUData;
function CPUVendor: String;
function CPUSpeedRaw(Delay: Cardinal): CPUDouble;
function CPUSpeed: Cardinal;

function PerfCounter: CPUDouble;
function PerfFreq: CPUDouble;
function RDTSC: Int64;
{$ENDIF}

implementation

{$IFDEF MSWINDOWS}
uses Windows, SysUtils;

resourcestring
  sCPU_Unknown         = '%s P%d Model %d';
  sCPU_Dual            = ' (Dual Processor)';
  sCPU_Model           = ' Model ';
  sCPU_Compatible      = ' (compatible)';

var
  FCPU: TCPUData;

function QPC(var C: CPUDouble): Bool; stdcall; external 'kernel32.dll' name 'QueryPerformanceCounter';
function QPF(var F: CPUDouble): Bool; stdcall; external 'kernel32.dll' name 'QueryPerformanceFrequency';

function PerfCounter: CPUDouble;
begin
  if not QPC(Result) then Result := GetTickCount
end;

function PerfFreq: CPUDouble;
begin
  if not QPF(Result) then Result := 1000
end;

function RDTSC: Int64;
asm
  rdtsc
end;

{CPU Routines}
function CPUType: Integer;
begin
  Result := FCPU.Family;
end;

function CPUSpeedRaw(Delay: Cardinal): CPUDouble;
var
  C: Int64;
  D: Double;
begin
  Result := 0;
  if FCPU.Features_EDX and ffTSC <> 0 then
  try // except Block needed, RDTSC can be a privilege Instruction !! but should never
    if Delay <= 0 then Delay := 10;
    D := PerfCounter;              // API QueryPerformanceCounter() based on a virtual 1.19318 MHz CPU
    {$IFDEF CPU386}
    asm
       PUSHAD
       DW     0310Fh               // RDTSC, read Time Stamp Counter into C
       MOV    C.DWord[0],EAX       // RDTSC is an CPU Clock based value
       MOV    C.DWord[4],EDX       // incremented on ONE CPU Clock.
       POPAD
    end;
    {$ELSE}
    C := RDTSC;
    {$ENDIF}
    Inc(Delay, GetTickCount);
    while GetTickCount < Delay do ;
    {$IFDEF CPU386}
    asm
       PUSHAD
       DW     0310Fh               // C := RDTSC - C
       SUB    EAX,C.DWord[0]
       SBB    EDX,C.DWord[4]
       ADD    EAX,5000             // subtract ~Cycles of follow API call
       ADC    EDX,0
       MOV    C.DWord[0],EAX
       MOV    C.DWord[4],EDX
       POPAD
    end;
    {$ELSE}
    C := RDTSC - C + 5000;
    {$ENDIF}
    D := PerfCounter - D;          
    Result := C * PerfFreq / D;
  except
  end;
end;

function CPUSpeed: Cardinal;
// returns corrected speed
{$J+}
const
  FSpeed: Cardinal = 0;
{$J-}
   FS1: array[0..47] of Word = (
      0,   25,   33,   60,   66,   75,   82,   90,
    100,  110,  116,  120,  133,  150,  166,  180,
    188,  200,  225,  233,  266,  300,  333,  350,
    366,  400,  415,  433,  450,  466,  500,  533,
    550,  600,  650,  667,  700,  733,  750,  800,
    833,  850,  866,  900,  933,  950,  966, 1000);
  FS2: array[0..5] of Byte = (
      0,   33,   50,   66,  100,  133);
var
  I,S: Integer;
begin
  if FSpeed = 0 then
  begin
    S := Round(CPUSpeedRaw(10) / 1000000);
    for I := Low(FS1) +1 to High(FS1) -1 do
      if (S = FS1[I]) or
         ((S >= FS1[I] - (FS1[I] - FS1[I -1]) div 2) and
          (S <  FS1[I] + (FS1[I +1] - FS1[I]) div 2)) then
      begin
        FSpeed := FS1[I];
        Break;
      end;
    if FSpeed = 0 then
    begin
      FSpeed := S;
      S := S mod 100;
      Dec(FSpeed, S);
      for I := Low(FS2) +1 to High(FS2) -1 do
        if (S = FS2[I]) or
           ((S >= FS2[I] - (FS2[I] - FS2[I -1]) div 2) and
            (S <  FS2[I] + (FS2[I +1] - FS2[I]) div 2)) then
        begin
          Inc(FSpeed, FS2[I]);
          Break;
        end;
    end;
  end;
  Result := FSpeed;
end;

function CPUData: TCPUData;
begin
  Result := FCPU;
end;

{check is CPUID Instruction present}
function CPUID_Found: LongBool; assembler;
asm
{$IFDEF CPU386}
       PUSHFD
       PUSHFD
       POP     EAX
       MOV     EDX,EAX
       XOR     EAX,0040000h
       PUSH    EAX
       POPFD
       PUSHFD
       POP     EAX
       XOR     EAX,EDX
       JZ      @@1
       PUSHFD
       POP     EAX
       MOV     EDX,EAX
       XOR     EAX,0200000h
       PUSH    EAX
       POPFD
       PUSHFD
       POP     EAX
       XOR     EAX,EDX
@@1:   POPFD
{$ELSE}
  pushfq
  pushfq
  pop    rax
  mov    rdx, rax
  xor    rax, 0040000h
  push   rax
  popfq
  pushfq
  pop    rax
  xor    rax, rdx
  jz     @@1
  pushfq
  pop    rax
  mov    rdx, rax
  xor    rax, 0200000h
  push   rax
  popfq
  pushfq
  pop    rax
  xor    rax, rdx
@@1:
  popfq
{$ENDIF}
end;

{$IFDEF CPUX64}
procedure DoCPUID64;
asm
       PUSH    RDI
       PUSH    RBX

       MOV     RDI,OFFSET FCPU
       LEA     RDI,[RDI].TCPUData.Vendor
       XOR     RAX,RAX
       CPUID
       MOV     [RDI + 0],EBX
       MOV     [RDI + 4],EDX
       MOV     [RDI + 8],ECX

       MOV     RDI,OFFSET FCPU
       CMP     EAX,2
       JL      @@1
       MOV     EAX,2
       CPUID
       MOV     [RDI].TCPUData.TLB_EAX,EAX
       MOV     [RDI].TCPUData.TLB_EDX,EDX
       MOV     [RDI].TCPUData.TLB_EBX,EBX
       MOV     [RDI].TCPUData.TLB_ECX,ECX
@@1:   MOV     EAX,1
       XOR     EBX,EBX
       XOR     ECX,ECX
       CPUID
       MOV     [RDI].TCPUData.Signature,EAX
       MOV     DWord Ptr [RDI].TCPUData.CPUID3[0],EAX
       MOV     [RDI].TCPUData.Features_EDX,EDX
       MOV     [RDI].TCPUData.Features_EBX,EBX
       MOV     [RDI].TCPUData.Features_ECX,ECX

       MOV     EDX,EAX
       AND     EAX,0Fh
       MOV     [RDI].TCPUData.Stepping,AL
       SHR     EDX,4
       MOV     EAX,EDX
       AND     EAX,0Fh
       MOV     [RDI].TCPUData.Model,AL
       SHR     EDX,4
       MOV     EAX,EDX
       AND     EAX,0Fh
       MOV     [RDI].TCPUData.Family,AL
       SHR     EDX,4
       AND     EDX,0Fh
       MOV     [RDI].TCPUData.Typ,DL

       MOV     EAX,080000000h
       XOR     EDX,EDX
       XOR     EAX,EAX
       CPUID
       TEST    EAX,EAX
       JLE     @@3
       AND     EDX,EDX
       JZ      @@3
       PUSH    RAX
       MOV     EAX,080000001h
       CPUID
       MOV     [RDI].TCPUData.FeaturesEx_EDX,EDX
       MOV     [RDI].TCPUData.FeaturesEx_EBX,EBX
       MOV     [RDI].TCPUData.FeaturesEx_ECX,ECX
       POP     RAX
       CMP     EAX,1
       JBE     @@3
       PUSH    RSI
       PUSH    RDI
       XOR     ESI,ESI
       LEA     RDI,[RDI].TCPUData.VendorEx
@@2:   LEA     EAX,[080000002h + ESI]
       XOR     EDX,EDX
       XOR     EBX,EBX
       XOR     ECX,ECX
       CPUID
       MOV     [RDI +  0],EAX
       MOV     [RDI +  4],EBX
       MOV     [RDI +  8],ECX
       MOV     [RDI + 12],EDX
       INC     ESI
       ADD     RDI,16
       AND     ESI,3
       JNZ     @@2
       POP     RDI
       POP     RSI

@@3:   XOR     EDX,EDX
       XOR     ECX,ECX
       XOR     EBX,EBX
       MOV     EAX,3
       CPUID
       MOV     DWord Ptr [RDI].TCPUData.CPUID3[ 4],EDX
       MOV     DWord Ptr [RDI].TCPUData.CPUID3[ 8],ECX
       MOV     DWord Ptr [RDI].TCPUData.CPUID3[12],EBX
       MOV     DWord Ptr [RDI].TCPUData.CPUID3[16],EAX
       POP     RBX
       POP     RDI
end;
{$ENDIF}

{initialize the CPU Datastruct}
procedure GetCPU;

  function CRC(const Value): Cardinal; assembler;
  asm
    {$IFDEF CPU386}
      MOV  EDX,EAX
      MOV  EAX,[EDX + 0]
      XOR  EAX,[EDX + 4]
      XOR  EAX,[EDX + 8]
    {$ELSE}
      mov  eax, [rcx+0]
      xor  eax, [rcx+4]
      xor  eax, [rcx+8]
    {$ENDIF}
  end;

{$IFDEF CPU386}
var
  ID: Word;
{$ENDIF}
begin
  FillChar(FCPU, SizeOf(FCPU), 0);
  if CPUID_Found then
  {$IFDEF CPU386}
  asm
       PUSH    EDI
       PUSH    EBX

       MOV     EDI,OFFSET FCPU
       LEA     EDI,[EDI].TCPUData.Vendor
       XOR     EAX,EAX
       DW      0A20Fh             //     CPUID
       MOV     [EDI + 0],EBX
       MOV     [EDI + 4],EDX
       MOV     [EDI + 8],ECX

       MOV     EDI,OFFSET FCPU
       CMP     EAX,2
       JL      @@1
       MOV     EAX,2
       DW      0A20Fh
       MOV     [EDI].TCPUData.TLB_EAX,EAX
       MOV     [EDI].TCPUData.TLB_EDX,EDX
       MOV     [EDI].TCPUData.TLB_EBX,EBX
       MOV     [EDI].TCPUData.TLB_ECX,ECX
@@1:   MOV     EAX,1
       XOR     EBX,EBX
       XOR     ECX,ECX
       DW      0A20Fh
       MOV     [EDI].TCPUData.Signature,EAX
       MOV     DWord Ptr [EDI].TCPUData.CPUID3[0],EAX
       MOV     [EDI].TCPUData.Features_EDX,EDX
       MOV     [EDI].TCPUData.Features_EBX,EBX
       MOV     [EDI].TCPUData.Features_ECX,ECX

       MOV     EDX,EAX
       AND     EAX,0Fh
       MOV     [EDI].TCPUData.Stepping,AL
       SHR     EDX,4
       MOV     EAX,EDX
       AND     EAX,0Fh
       MOV     [EDI].TCPUData.Model,AL
       SHR     EDX,4
       MOV     EAX,EDX
       AND     EAX,0Fh
       MOV     [EDI].TCPUData.Family,AL
       SHR     EDX,4
       AND     EDX,0Fh
       MOV     [EDI].TCPUData.Typ,DL

       MOV     EAX,080000000h
       XOR     EDX,EDX
       XOR     EAX,EAX
       DW      0A20Fh
       TEST    EAX,EAX
       JLE     @@3
       AND     EDX,EDX
       JZ      @@3
       PUSH    EAX
       MOV     EAX,080000001h
       DW      0A20Fh
       MOV     [EDI].TCPUData.FeaturesEx_EDX,EDX
       MOV     [EDI].TCPUData.FeaturesEx_EBX,EBX
       MOV     [EDI].TCPUData.FeaturesEx_ECX,ECX
       POP     EAX
       CMP     EAX,1
       JBE     @@3
       PUSH    ESI
       PUSH    EDI
       XOR     ESI,ESI
       LEA     EDI,[EDI].TCPUData.VendorEx
@@2:   LEA     EAX,[080000002h + ESI]
       XOR     EDX,EDX
       XOR     EBX,EBX
       XOR     ECX,ECX
       DW      0A20Fh
       MOV     [EDI +  0],EAX
       MOV     [EDI +  4],EBX
       MOV     [EDI +  8],ECX
       MOV     [EDI + 12],EDX
       INC     ESI
       ADD     EDI,16
       AND     ESI,3
       JNZ     @@2
       POP     EDI
       POP     ESI

@@3:   XOR     EDX,EDX
       XOR     ECX,ECX
       XOR     EBX,EBX
       MOV     EAX,3
       DW      0A20Fh
       MOV     DWord Ptr [EDI].TCPUData.CPUID3[ 4],EDX
       MOV     DWord Ptr [EDI].TCPUData.CPUID3[ 8],ECX
       MOV     DWord Ptr [EDI].TCPUData.CPUID3[12],EBX
       MOV     DWord Ptr [EDI].TCPUData.CPUID3[16],EAX
       POP     EBX
       POP     EDI
  end else
  try
    FCPU.Family := cf386;
    asm
       XADD    EAX,EAX
       BSWAP   EAX

       PUSH    EDI
       MOV     EDI,OFFSET FCPU
       MOV     [EDI].TCPUData.Family,cf486
       MOV     EAX,CR0
       AND     EAX,not 010h
       MOV     CR0,EAX
       MOV     EAX,CR0
       AND     EAX,    010h
       JZ      @@1
       INC     [EDI].TCPUData.Model
       OR      ID,1
       FNINIT
       FNSTSW  ID
       CMP     ID[0],0
       JNE     @@1
       FNSTCW  ID
       MOV     AX,ID
       AND     AX,013Fh
       CMP     AX,003Fh
       JNE     @@1
       INC     [EDI].TCPUData.Model
@@1:   POP     EDI
    end;
  except
  end;
  {$ELSE}
     DoCPUID64;
  {$ENDIF}
  FCPU.VendorID := CRC(FCPU.Vendor);
end;

function CPUVendor: String;
var
  Compatible: Boolean;

  function L2Cache: Cardinal;
  begin // find L2 Cache definition
    Result := FCPU.TLB_EDX;
    while (Result and $40 = 0) and (Result <> 0) do Result := Result shr 8;
    Result := Result and $FF;
  end;

label
  Unknown, Skip;
begin
  Compatible := False;
  with FCPU do
  begin
    case VendorID of
      // Intel ----------------------------
      cvIntel:
        begin
          Result := 'Intel ';
          // use gotos, yes, not realy good coding style, but I want a compact solution
          goto Skip;
Unknown:
          Compatible := True;
Skip:
          case Family of
            cf386: Result := Result + '386';
            cf486:
              case Model of
              // on the way a small remark:
              // we use here concacted stringconstant,
              // compiler save optimated only once on different version into code,
              // and so we reduce the codesize.
                0: Result := Result + '486' + 'DX' + '25/30';
                1: Result := Result + '486' + 'DX' + '50';
                2: Result := Result + '486' + 'SX';
                3: Result := Result + '486' + 'DX' + '2';
                4: Result := Result + '486' + 'SL';
                5: Result := Result + '486' + 'SX' + '2';
                7: Result := Result + '486' + 'DX' + '2' + ' WB enhanced';
                8: Result := Result + '486' + 'DX' + '4';
                9: Result := Result + '486' + 'DX' + '4' + ' WB enhanced';
              else
                Result := Result + '486' + sCPU_Model + IntToStr(Model);
              end;
            cfPentium:
              case Model of
                0: Result := Result + 'Pentium' + ' P5' + ' A-step';
                1: Result := Result + 'Pentium' + ' P5';
                2: Result := Result + 'Pentium' + ' P5' + '4C';
                3: Result := Result + 'Pentium' + ' P5' + '4T' + ' ' + 'overdrive';
                4: Result := Result + 'Pentium' + ' P5' + '5C';
                7: Result := Result + 'Pentium' + ' P5' + '4C';
                8: Result := Result + 'Pentium' + ' P5' + '5C' + ' (0.25 µm)';
              else
                Result := Result + 'Pentium' + sCPU_Model + IntToStr(Model);
              end;
            cfPentiumPro:
              case Model of
                0: Result := Result + 'Pentium' + ' Pro (P6)' + ' A-step';
                1: Result := Result + 'Pentium' + ' Pro (P6)';
                3: Result := Result + 'Pentium' + ' II' + ' (0.28 µm)';
                5: begin
                     Result := Result + 'Pentium' + ' II' + ' (0.25 µm)';
                     case L2Cache of
                       0: Result := Result + ' Celeron';
                 $44,$45: Result := Result + ' Xenon';
                     end;
                   end;
                6: Result := Result + 'Pentium' + ' II' + ' L2 Cache';
              7,8: begin
                     Result := Result + 'Pentium';
                     case Features_EBX and $FF of
                       1: Result := Result + ' Celeron';
                       3: Result := Result + ' III' + ' Xenon';
                       8: Result := Result + ' IV'; // ? not really sure about
                     else
                       begin
                         Result := Result + ' III';
                         if L2Cache in [$44,$45] then Result := Result + ' Xenon';
                       end;
                     end;
                     if Model = 7 then Result := Result + ' (0.25 µm)'
                       else Result := Result + ' (0.18 µm)';
                   end;
               10: Result := Result + 'Pentium' + ' III' + ' Xenon';
              else
                Result := Result + 'Pentium' + ' II' + sCPU_Model + IntToStr(Model);
              end;
          else
            Result := Format(sCPU_Unknown, [Vendor, Family, Model]);;
          end;
        end;
      // AMD ----------------------------
      cvAMD:
        begin
          Result := 'AMD ';
          case Family of
            cf486:
              case Model of
                14: Result := Result + '586';
                15: Result := Result + '586' + ' WB enhanced';
              else
                goto Unknown;
              end;
            cfPentium:
              case Model of
                0: Result := Result + 'K5' + ' SSA5' + ' (PR75, PR90, PR100)';
                1: Result := Result + 'K5' + ' 5k86' + ' (PR120, PR133)';
                2: Result := Result + 'K5' + ' 5k86' + ' (PR166)';
                3: Result := Result + 'K5' + ' 5k86' + ' (PR200)';
                6: Result := Result + 'K6' + ' (0.30 µm)';
                7: Result := Result + 'K6' + ' (0.25 µm)';
                8: Result := Result + 'K6' + ' II';
                9: Result := Result + 'K6' + ' III';
               13: Result := Result + 'K6' + ' II+ or III+';
              else
                goto Unknown;
              end;
            cfPentiumPro:
              case Model of
                1: Result := Result + 'K7' + ' Athlon' + ' (0.25 µm)';
                2: Result := Result + 'K7' + ' Athlon' + ' (0.18 µm)';
              3,4: Result := Result + 'K7' + ' Athlon';
              else
                goto Unknown;
              end;
          else
            goto Unknown;
          end;
        end;
      // Cyrix ----------------------------
      cvCyrix:
        begin
          Result := 'Cyrix ';
          case Family of
            cf486:
              case Model of
                4: Result := Result + '586' + ' Media GX';
                9: Result := Result + '586'
              else
                goto Unknown;
              end;
            cfPentium:
              case Model of
                2: Result := Result + 'M1' + ' 6x86';
                4: Result := Result + 'GXm';
              else
                goto Unknown;
              end;  
            cfPentiumPro:
              case Model of
                0: Result := Result + 'M2' + ' 6x86' + 'MX';
                5: Result := Result + 'M2' + ' VIA III';
              else
                goto Unknown;
              end;  
          else
            goto Unknown;
          end;
        end;
      // UMC ----------------------------
      cvUMC:
        begin
          Result := 'UMC ';
          if Family = cf486 then
            case Model of
              1: Result := Result + 'U5D';
              2: Result := Result + 'U5S';
            else
              goto Unknown;
            end
          else goto Unknown;
        end;
      // NexGen ----------------------------
      cvNexGen:
        begin
          Result := 'NexGen ';
          if (Family = cfPentium) and (Model = 0) then Result := Result + '586'
            else goto Unknown;
        end;
      // Centaur/IDT ----------------------------
      cvCentaur:
        begin
          Result := 'Centaur/IDT ';
          if Family = cfPentium then
            case Model of
              4: Result := Result + 'C6';
              8: Result := Result + 'C2';
              9: Result := Result + 'C3';
            else
              goto Unknown;
            end
          else goto Unknown;
        end;
      // Rise Technology ----------------------------
      cvRise:
        begin
          Result := 'Rise Technology ';
          if Family = cfPentium then
            case Model of
              0: Result := Result + 'mP6' + ' (0.25 µm)';
              2: Result := Result + 'mP6' + ' (0.18 µm)';
            else
              goto Unknown;
            end
          else goto Unknown;
        end;
    else
      goto Unknown;
    end;
    if (Features_EDX and ffMMX <> 0) and (Pos('MMX', Result) = 0) then
      Result := Result + ' ' + 'MMX';
    if (Typ = ctOverdrive) and (Pos('overdrive', Result) = 0) then
      Result := Result + ' ' + 'overdrive';
    if (Typ = ctDual) and (Pos(sCPU_Dual, Result) = 0) then
      Result := Result + sCPU_Dual;
    if Compatible then
      Result := Result + sCPU_Compatible;
    if VendorEx[0] <> #0 then
      Result := Result + ' "' + Trim(StrPas(PChar(String(VendorEx)))) + '"';
  end;
end;

initialization
  GetCPU;
{$ENDIF}

end.
