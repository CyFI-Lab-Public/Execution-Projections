```
CFLAGS="-O0 -g" ./configure
make
./grep-3.11/src/grep -E '^([A-Za-z]+( [A-Za-z]+)*) - \[(ERROR|WARN|INFO)\] ([0-9]{4}-[0-9]{2}-[0-9]{2}) <([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>$' testfile.txt
```