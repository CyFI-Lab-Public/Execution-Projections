# Helper function to set rbreak and attach commands to it
define set_rbreak_with_commands
    rbreak $arg0
    commands
        if $_function
            printf "Function: %s, Address: %p\n", $_function, $pc
        else
            printf "Function: [unknown], Address: %p\n", $pc
        end
        backtrace 3
        continue
    end
end

# Log the base address
break main
commands
    printf "Base address: %p\n", $pc
    continue
end

# Set breakpoints on all functions in grep’s src directory
set_rbreak_with_commands grep.c:.
set_rbreak_with_commands dfasearch.c:.
set_rbreak_with_commands kwsearch.c:.
set_rbreak_with_commands kwset.c:.
set_rbreak_with_commands pcresearch.c:.
set_rbreak_with_commands searchutils.c:.

# Run the program
run
