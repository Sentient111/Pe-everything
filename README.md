# Pe everything
 
little fun project that got bigger than expected. Feel free to give feedback.

todo:
-add bound checks and max sizes to read/write operations for more robust code
-fix driver relocs (no clue what goes wrong there tbh)
-improve import/export walking to support only getting a wanted import/export and not the whole dir.
-remote call cannot be used without function arguments (blyat)
-do some slight changed to error handeling so the error struct has a fixed size between architectures
-I think targeting a x64 process while being in x86 will cause some problems because no wow64 win api is used (cba to test rn)
