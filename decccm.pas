{
    NIST Special Publication 800-38C
    Recommendation for Block Cipher Modes of Operation:
                   The CCM Mode for Authentication and Confidentiality
}
unit DECccm;

{$ifdef FPC}
{$mode Delphi}
{$endif}

interface

uses
  Classes, SysUtils
  , DECCipher
  ;

type
  { USAGE:
          // calculate MIC
          ciph.init( key, IV, 0);
          ciph.mic_setup(a, sizeof(a), sizeof(data), sizeof(mic));
          ciph.mic_encode(data, sizeof(data));
          ciph.mic_hash(mic, sizeof(mic) );
          // encode ccm-cyphed data
          ciph.encode(data, textcoded, sizeof(data));
          ciph.done()

          // decode ccm-cyphed data
          ciph.decode_setup(sizeof(data));
          ciph.decode(textcoded, data, sizeof(data));

          // calculate mic on ccm-decyphed data
          ciph.mic_setup(a, sizeof(a), sizeof(data), sizeof(mic));
          ciph.mic_encode(data, sizeof(data));
          ciph.mic_hash(validate_mic, sizeof(mic) );

          ok := memcmp(mic[0], validate_mic[0], sizeof(mic) ) = 0;
  }
  TDEC_CCM = class(TCipher_AES)
  public

    // @value q = 0 - adjust counter width enough for dsize
    procedure mic_setup( const attr; asize : word ;
                             dsize: LongWord;
                             msize: byte;
                             q : byte = 0       // counter bytes
                             );

    procedure mic_encode(var data; dsize: LongWord );
	
	/// @brief produce MIC of encoded data, and prepare chiper for data 
	///		encode as CCM specified - CTR-mode coding
    procedure mic_hash(var mic; msize: byte );

	/// @brief prepare chiper for data decode as CCM specified - CTR-mode coding
    // @value q = 0 - adjust counter width enough for dsize
    procedure decode_setup(dsize: word; q : byte = 0       // counter bytes
                                    );

    // @arg qw - counter width
    function  ccm_counter_width(dsize: LongWord ) : word;
	// @brief make IV proposed by CCM for data encription - a CTR-mode IV
    procedure ccmiv_counter(var ctriv; cnt: LongWord; qw : byte );
    function  ccmiv_counter(cnt: LongWord; qw : byte ) : TBytes;

    protected
      // @brief - copy tmp <- last key-sized data block
      // @return 0 - sz aligned to key-block size
      // @return > 0 - size of last data key-sized block
      function pad_zero(var dst; const data; sz : word) : word;
  end;

implementation
uses DECutil;

resourcestring
  sMICSizeInvalid = 'MIC-size invalid';
  sCTRSizeInvalid = 'CCM: counter size must <= 8';

function len_bytes( dsize: LongWord ) : byte;
const    BLOCK_SIZE : word = 16;
var      q: byte;
begin
  for q := 1 to 8 do begin
      dsize := dsize >> 8;
      if dsize <= 0 then break;
  end;
  result := q;
end;

// @result: Buffer = B0
procedure TDEC_CCM.mic_setup(const attr; asize : word ;
                             dsize: LongWord; msize: byte;
                             q : byte = 0       // counter bytes
                             );
var
  b0 : TBytes = [];
  tmp: TBytes = [];
  ksize: byte;
  t  : byte;
  w  : word;
  pos: LongWord;
  sz : LongWord;
  pd : PByteArray;

const
    BLOCK_SIZE : word = 16;

    function aligned_sz(sz : word) : word;
    begin
        result := sz and not (ksize-1);
    end;

begin
  // validate msize
  if (msize < 2) then
      raise EDECException.Create(sMICSizeInvalid);

  t := (msize-2) div 2;

  if (t > 7) then
     raise EDECException.Create(sMICSizeInvalid);
  if ( ((t*2)+2) <> msize ) then
     raise EDECException.Create(sMICSizeInvalid);

  ksize := IVSize;
  SetLength(b0, ksize);
  move(IV[0], b0[0], ksize);

  // adjust q-size
  if (q = 0) then
     q := len_bytes(dsize);
  if (q > 8) then         //not supports yet 64 bitdata size
      raise EDECException.Create(sCTRSizeInvalid);
  q -= 1;

  // fill dsize into b0.counter
  sz := dsize;
  for w := ksize-1 downto ksize-1-q do begin
      b0[w] := sz and $ff;
      sz := sz >> 8;
  end;

  b0[0] := q or (t<< 3);
  if (asize > 0) then
    b0[0] := b0[0] or $40;


    Done();
    mode := cmCBCx;
    move(b0[0], FBuffer[0], ksize);    // Buffer = B0


    setlength(tmp, ksize);
    FillByte( Feedback[0], ksize, 0);
    encode( b0[0], tmp[0], ksize);

    // mic append attr
    if (asize > 0) then begin
      setlength(tmp, asize+10+15);

      // prepare attr header
      if (asize < $ff00) then begin
        tmp[0] := asize >> 8;
        tmp[1] := asize and $ff;
        pos := 2;
      end
      else begin
        tmp[0] := $ff;
        if (asize <= $ffffffff) then begin
          tmp[1] := $fe;
          SwapLongBuffer(asize, tmp[2], 4);
          pos := 6;
        end
        else begin
          tmp[1] := $ff;
          SwapInt64Buffer(asize, tmp[2], 8);
          pos := 10;
        end;
      end;

      pd := @attr;
      move( attr, tmp[pos], asize);

      sz := aligned_sz(asize + pos);
      if sz > 0 then
          encode( tmp[0], tmp[0], sz);

      // padding last block by zeros
      sz := pad_zero( tmp[0], tmp[0], asize + pos);
      if (sz > 0) then
         encode( tmp[0], tmp[0], ksize);
    end;
end;

procedure TDEC_CCM.mic_encode(var data; dsize: LongWord );
var
  tmp: TBytes = [];
  sz : LongWord;

  function aligned_sz(sz : word) : word;
  begin
      result := sz and not (IVSize-1);
  end;

begin
  setlength(tmp, dsize+15);
  sz := aligned_sz(dsize);
  if sz > 0 then begin
      encode( data, tmp[0], sz);
  end;

  // padding last block by zeros
  sz := pad_zero(tmp[0], data, dsize);
  if (sz > 0) then
     encode( tmp[0], tmp[0], IVSize);
end;

procedure TDEC_CCM.mic_hash(var mic; msize: byte );
var
   q: byte;
   ksize: byte;
   tmp: TBytes = [];
begin
  ksize := IVSize;
  setlength(tmp, ksize);
  move(Feedback[0], tmp[0], ksize);   // tmp = T value
  q := FBuffer[0] and 7;

  // MIC = CTR(0, T)
  FState := csDone;
  if (q <= 1) then
     mode := cmCTR2
  else
     mode := cmCTR4;

  // make CTR0 IV <= B0
  move(FBuffer[0], Feedback[0], ksize);
  q := FBuffer[0] and 7;
  Feedback[0] := q; //b0[0] and 7;
  FillByte( Feedback[ksize-1-q], q+1, 0);

  encode( tmp[0], tmp[0], ksize);

  move(tmp[0], mic, msize);
end;


procedure TDEC_CCM.decode_setup(dsize: word; q : byte = 0       // counter bytes
                         );
var
  ksize: byte;
begin

  // adjust q-size
  if (q = 0) then
     q := len_bytes(dsize);
  if (q > 8) then         //not supports yet 64 bitdata size
      raise EDECException.Create(sCTRSizeInvalid);
  q -= 1;

    Done();

    if (q <= 1) then
       mode := cmCTR2
    else
       mode := cmCTR4;

    ksize := IVSize;
    // init into b0.counter = 1, for data encoding phase
    Feedback[0] := q;
    FillByte( Feedback[ksize-1-q], q+1, 0);
    Feedback[ksize-1] := 1;
end;

// @result tmp[0] <= padded rest of last aligned block
function TDEC_CCM.pad_zero(var dst; const data; sz : word) : word;
var
  d   : PByteArray;
  tmp : PByteArray;
  rest: word;
  ksize: byte;

  function aligned_sz(sz : word) : word;
  begin
      result := sz and not (ksize-1);
  end;

begin
    ksize := IVSize;
    rest := sz - aligned_sz(sz);
    result := rest;

    if ( rest = 0 ) then begin
      exit;
    end;

    d := PByteArray(@data);
    tmp := PByteArray(@dst);
    move( d[sz-rest], tmp[0], rest);
    rest :=  ksize - rest;
    FillByte( tmp[result], rest, 0);
end;

// @arg qw - counter width
function  TDEC_CCM.ccm_counter_width(dsize: LongWord ) : word;
begin
  result := len_bytes(dsize);
end;

function  TDEC_CCM.ccmiv_counter(cnt: LongWord; qw : byte ) : TBytes;
begin
  setLength(result, IVSize );
  ccmiv_counter( result[0], qw );
end;

procedure TDEC_CCM.ccmiv_counter(var ctriv; cnt: LongWord; qw : byte );
var
  ksize : byte;
  ivb : PByteArray;
begin
  ksize := IVSize;
  move(IV[0], ctriv, ksize);
  ivb := PByteArray(@ctriv);

  ivb[0] := qw-1;
  FillByte( ivb[ksize-qw], qw, 0);
  cnt := SwapLong(cnt+1);

  if (qw > sizeof(cnt)) then
     qw := sizeof(cnt);
  move( cnt, ivb[ksize-qw], qw);
end;

end.

