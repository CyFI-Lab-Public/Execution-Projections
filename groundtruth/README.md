
## Setup
```sh
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz
tar -zxf pin-external-3.31-98869-gfa6f126a8-gcc-linux.tar.gz
cd pin-external-3.31-98869-gfa6f126a8-gcc-linux/source/tools/ManualExamples
```

## Add custom PinTools to ManualExamples/ and adapt makefile.rules

## program: ls

```sh
$ cd source/tools/ManualExamples
$ make all
$ ../../../pin -t obj-intel64/blocktrace_main.so -- ls
```


## program: grep

```sh
$ ../../../pin -t obj-intel64/blocktrace_main.so -- ~/exec-proj/grep/grep-3.11/src/grep -E '^([A-Za-z]+( [A-Za-z]+)*) - \[(ERROR|WARN|INFO)\] ([0-9]{4}-[0-9]{2}-[0-9]{2}) <([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>$' /home/dinko/exec-proj/grep/testfile.txt
```
