# Set breakpoints on all functions in grep’s source file
rbreak grep

# Define the logging command for all these breakpoints
commands
    if $_function
        printf "Function: %s, Address: %p\n", $_function, $pc
    else
        printf "Function: [unknown], Address: %p\n", $pc
    end
    backtrace 5
    continue
end

# Run the program
run
