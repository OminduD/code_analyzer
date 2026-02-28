{ test.pas }
program TestProgram;
uses Dos;

var
  p: Pointer;

begin
  { VULNERABILITY PASCAL001 }
  GetMem(p, 1024);
  
  { VULNERABILITY PASCAL002 }
  Exec('/bin/sh', '-c "echo hello"');
end.
