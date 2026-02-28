-- test.adb
with Ada.Unchecked_Conversion;
with Ada.Unchecked_Deallocation;

procedure Test is

   type Int_Ptr is access Integer;
   
   -- VULNERABILITY ADA001
   function Convert is new Ada.Unchecked_Conversion(Integer, Float);

   procedure Free is new Ada.Unchecked_Deallocation
     (Object => Integer, Name => Int_Ptr);

   -- VULNERABILITY ADA002
   Ptr : Int_Ptr := new Integer'(42);

begin
   Free(Ptr);
end Test;
