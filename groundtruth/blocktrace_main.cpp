/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <fstream>
#include "pin.H"
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;

ofstream OutFile;
ofstream DBGFile;

// The running count of instructions is kept here
// make it static to help the compiler optimize docount
static UINT64 icount = 0;

const ADDRINT base_address = 0x555555554005;
// This function is called before every block
VOID trace_bbl(ADDRINT addr)
{
    OutFile << "0x" << std::hex << (addr - base_address) << endl;
}

// Pin calls this function every time a new basic block is encountered
// It inserts a call to docount
VOID Trace(TRACE trace, VOID* v)
{

    /*
    * MAIN executable analysis
    */
    ADDRINT curr_addr = TRACE_Address(trace);
    IMG current_image = IMG_FindByAddress(curr_addr);
    BOOL is_valid = IMG_Valid(current_image);
    BOOL is_main = false;
    if (is_valid) {
        is_main = IMG_IsMainExecutable(current_image);
        if (is_main) {
            DBGFile << "main -> 0x" << std::hex << IMG_LowAddress(current_image) << endl;
        } else {
            DBGFile << "----- NOT main -----" << endl;
        }
    } else {
        DBGFile << "----- invalid -----" << endl;
    }

    /*
    * RTN routine name analysis
    */
    // RTN rtn = TRACE_Rtn(trace);
    // if (RTN_Valid(rtn)) {
    //     const std::string name = RTN_Name(rtn);
    //     DBGFile << "name: " << name << endl;
    // } else {
    //     DBGFile << "INVALID rtn" << endl;
    // }
    // else {
    //     std::cout << "is not main" << endl;
    // }

    if (is_valid && is_main) {
        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
        {
            ADDRINT addr = BBL_Address(bbl);
            // Insert a call to docount before every bbl, passing the number of instructions
            BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)trace_bbl, IARG_UINT64, addr, IARG_END);
        }
    }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "blocktrace_main.out", "specify output file name");
KNOB< string > KnobDebugFile(KNOB_MODE_WRITEONCE, "pintool", "d", "blocktrace_main_debug.out", "specify debug file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.setf(ios::showbase);
    OutFile << "Count " << icount << endl;
    OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool records the addresses of all basic blocks executed within the main executable." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());
    DBGFile.open(KnobDebugFile.Value().c_str());

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register Fini to be called when the application exits
    // PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
