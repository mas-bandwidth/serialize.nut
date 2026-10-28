// the UBSan leg's reversed witness (make/ubsan.mk): a signed overflow in a
// script must halt the UBSan interpreter, or the leg proves nothing
local x = 0x7FFFFFFFFFFFFFFF;
local y = x + vargv.len() + 1;
print("witness ran past the overflow: " + y + "\n");
