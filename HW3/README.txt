crackme1

-passcode: 047050047067074069071063061068

Steps:
    - Launch Ghidra and open crackme1
    - Find "Your number corresponds to %s, well done!"
    - Strcmp is with 363GNIKCAH
    - Following the logic in the while loop, every 3 characters are interpreted as numbers with atoi() and turned into a corresponding character 
    - This character when added by \x04 corresponds to a character in 363GNIKCAH
    - Make sure the 3rd character in input number (as string) is 7 and 5th char which is overflowed is a 5
    - The numbers corresponding to each character in 363GNIKCAH subtracted by \x04 is 
    - 47 50 47 67 74 69 71 63 61 68

crackme2

-passcode: SBU^CSE363^2025

Steps:
    - Launch Ghidra and open crackme2
    - Find the main function where "Usage: %s <key>\n" is
    - Follow logic and rename corresponding functions for readability
    - Function that calls another "XOR26" function on "IXODYI_),)D(*(/" is the key to getting the correct input
    - The input should match that value of the "XOR26" function which returns a new string with each character XOR'd with 26
    - 'I' ^ 26 -> 'S'
    - 'X' ^ 26 -> 'B'
    - 'O' ^ 26 -> 'U'
    - 'D' ^ 26 -> '^'
    - 'Y' ^ 26 -> 'C'
    - 'I' ^ 26 -> 'S'
    - '_' ^ 26 -> 'E'
    - ')' ^ 26 -> '3'
    - ',' ^ 26 -> '6'
    - ')' ^ 26 -> '3'
    - 'D' ^ 26 -> '^'
    - '(' ^ 26 -> '2'
    - '*' ^ 26 -> '0'
    - '(' ^ 26 -> '2'
    - '/' ^ 26 -> '5'
