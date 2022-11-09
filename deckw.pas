{
    NIST Special Publication 800-38F. December 2012
    Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping

    RFC-3394 Advanced Encryption Standard (AES) Key Wrap Algorithm
}
unit DECKW;

{$ifdef FPC}
{$mode Delphi}
{$endif}

interface

uses
  Classes, SysUtils
  , DECCipher
  ;

type
  TDEC_KW = class(TCipher_AES)
  public
    // @arg dest - output buffer, MUST have space DataSize+8
    // @return dest size
    function wrap  (const Source; DataSize: word; var Dest ): word;

    // @arg dest - output buffer, MUST have space DataSize-8
    // @return dest size
    // @return 0 - unwraped no key
    function unwrap(const Source; DataSize: word; var Dest ): word;

    const ICV1 : qword = $a6a6a6a6a6a6a6a6;
  end;

implementation
uses DECUtil;

resourcestring
  sKWSizeInvalid = 'KW-size should have 8byte*(n >= 3)';


function TDEC_KW.wrap  (const Source; DataSize: word; var Dest): word;
var
    n : word;
    i : word;
    j : byte;
    t : qword;
    A : qword;

    s : PByteArray;
    d : PByteArray;
    b : PByteArray;
    bA: PQword;
begin
    if ((DataSize and 7) <> 0) then
      raise EDECException.Create(sKWSizeInvalid);

    n := DataSize div 8;
    if (n < 2) then
      raise EDECException.Create(sKWSizeInvalid);

{$if 0}
     // adress should aligned too?
{$endif}

    mode := cmECBx;

    b := FFeedback;
    bA := PQword(b);


    s := PByteArray(@source);
    d := PByteArray(@dest);
    //move(d[0], ba, 8);
    move(s[0], d[8], DataSize);

    bA[0] := ICV1;

    t := 0;
    for j := 0 to 5 do begin
      for i := 1 to n do begin
        move(d[i*8], b[8], 8);
        DoEncode(b, b, 16);
        move(b[8], d[i*8], 8);

        bA[0] := bA[0] xor SwapInt64(t+i);
      end;
      t += n;
    end;
    move(bA[0], d[0], 8);

    result := DataSize+8;
end;

function TDEC_KW.unwrap(const Source; DataSize: word; var Dest) : word;
var
    n : word;
    i : word;
    j : byte;
    t : qword;
    A : qword;

    s : PByteArray;
    d : PByteArray;
    b : PByteArray;
    bA: PQword;
begin
    if ((DataSize and 7) <> 0) then
      raise EDECException.Create(sKWSizeInvalid);

    n := DataSize div 8;
    if (n < 3) then
      raise EDECException.Create(sKWSizeInvalid);
    dec(n);

{$if 0}
     // adress should aligned too?
{$endif}

    mode := cmECBx;

    b := FFeedback;
    bA := PQword(b);


    s := PByteArray(@source);
    d := PByteArray(@dest);
    move(s[0], ba[0], 8);
    move(s[8], d[0], DataSize);

    for j := 5 downto 0 do begin
      t := n*j;
      for i := n-1 downto 0 do begin
        move(d[i*8], b[8], 8);
        bA[0] := bA[0] xor SwapInt64(t+i+1);
        DoDecode(b, b, 16);
        move(b[8], d[i*8], 8);
      end;
    end;

    if (bA[0] = ICV1) then
        result := DataSize-8
    else
        result := 0;
end;

end.

