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

// Global map to store function names
std::map<ADDRINT, std::string> func_name_map;

const ADDRINT base_address = 0x555555554005;
const ADDRINT angr_base = 0x400000;
// This function is called before every block
VOID trace_bbl(ADDRINT addr, ADDRINT rtn_addr)
{
    OutFile << "0x" << std::hex << (addr - base_address);
    if (rtn_addr != 0 && func_name_map.count(rtn_addr) > 0) {
        OutFile << " --> " << func_name_map[rtn_addr];
    } else {
        OutFile << " --> (unknown)";
    }
    OutFile << endl;
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
            DBGFile << "main -> 0x" << std::hex << IMG_LowAddress(current_image);
        } else {
            DBGFile << "----- NOT main -----";
        }
    } else {
        DBGFile << "----- invalid -----";
    }

    /*
    * RTN routine name analysis
    */
    RTN rtn = TRACE_Rtn(trace);
    std::string func_name = "(unknown)";
    ADDRINT rtn_addr = 0;
    if (RTN_Valid(rtn)) {
        func_name = RTN_Name(rtn);
        rtn_addr = RTN_Address(rtn);
        // Store function name with address as key
        func_name_map[rtn_addr] = func_name;
        DBGFile << "\tfunc: " << func_name << ", addr: " << rtn_addr << endl;
    } else {
        DBGFile << "\tINVALID rtn_name" << endl;
    }

    if (is_valid && is_main) {
        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
        {
            ADDRINT addr = BBL_Address(bbl);
            // Insert a call to docount before every bbl, passing the number of instructions
            BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)trace_bbl, IARG_UINT64, addr, IARG_UINT64, rtn_addr, IARG_END);
        }
    }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "blocktrace_main_base.out", "specify output file name");
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

    PIN_InitSymbols(); // Call this early in your tool's initialization

    // Register Instruction to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register Fini to be called when the application exits
    // PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
