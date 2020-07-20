# snort-2.9_RTDS
1. Compile netmap:
    Go to the folder ./netmap/LINUX
    Read the README.md
    Follow the intructions in compiling and installing
    
2. Compile daq-2.0.6
    Go to the folder ./daq-2.0.6
    Read the README
    Follow the instructions in compiling and installing

3. Compile snort-2.9 
    Go to the folder ./snort-2.9
    Execute the script snortConfig using the command ./snortConfig
    The above step will clean, configure, compile and install
    If this fails look at the errors and install the dependencies required and run the script again

Running SNORT
You will need 5 interfaces to run SNORT and Tc together witha separate interface as the control interface.

Open the setupBridge script and change the interface names p7p1, p3p1, p5p1 and p1p1 into the interfaces that you have on your Linux PC. Save the script and run it.

Then open the script runSnort and change the interface names p3p1 and p7p1 into the ones that you have on your PC.

Connect the interfaces as shown in the wiki

Excute the script runSnort using the command ./runSnort



    
    
