# exec-proj

## Scenario
Nginx has generated some logs (`nginx/error_single.log`) and we want to recreate the execution.   

## Setup Instructions                                                                      
This repository uses angr-dev as a submodule for development environment setup.

Requirement: Python 3.10
You can satisfy with:
    ```bash
    sudo add-apt-repository ppa:deadsnakes/ppa
    sudo apt update
    sudo apt install python3.10 python3.10-venv
    ```

1. Clone this repository with submodules:
    ```bash
    git clone --recursive https://github.com/CyFI-Lab-Public/Execution-Projections.git &&
    cd Execution-Projections
    ```

2. Set up the development enviornment
    ```bash
    cd angr-dev &&
    ./setup.sh -i -e angr
    ```

3. Create and activate the venv and install requirements
    ```bash
    cd .. &&
    sudo apt install python3-full python3-venv &&
    python3.10 -m venv ~/.virtualenvs/angr &&
    source ~/.virtualenvs/angr/bin/activate &&
    pip install virtualenvwrapper &&
    export WORKON_HOME=$HOME/.virtualenvs &&
    source ~/.local/bin/virtualenvwrapper.sh &&
    workon angr && 
    pip install -r requirements.txt
    ```

4. Apply any modifications to the angr-dev repos
    ```bash
    cp angr-mods/fprintf.py angr-dev/angr/angr/procedures/libc/fprintf.py
    ```

5. Enter source dir and run the demo.
    ```bash
    cd src && 
    python angr_script.py > ../out/nginx_out_demo.log
    ```

## Output
You will observe 2 important output files:
- The output file `out/nginx_out_demo.log`, which shows (1) the parsed log messages from `nginx/error_single.log` mapped to addresses in the nginx binary, (2) hooks installed in the binary before execution, (3) confirmation that the attributed log sites/addresses exist in the CFG, and (4) information about angr's exploration from each checkpoint (beginning at the entry point of the binary) to the next log site. You can see an example here: out/nginx_out_example.log
- The logging and debug file `src/debug_nginx_5000_demo.log`, which contains (1) logging during CFG generation, and (2) extensive information about each step (basic block execution) during symbolic execution (ctrl+f for `=== Explore 0 ===`). You can see an example here: src/debug_nginx_5000_example.log

## Note
- Importantly, the nginx.conf file (`nginx/nginx.conf`) is concretized to enforce proper initialization of nginx before entering the process-events loop.
