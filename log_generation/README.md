## grep
```sh
gdb -x trace_src_functions.gdb --args ../grep/grep-3.11/src/grep -E '^([A-Za-z]+( [A-Za-z]+)*) - \[(ERROR|WARN|INFO)\] ([0-9]{4}-[0-9]{2}-[0-9]{2}) <([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>$' testfile.txt | tee /home/dinko/exec-proj/log/grep/function_trace_BRsrc.log
```

## nginx
```sh
sudo gdb -x trace_src_functions.gdb --args /usr/local/nginx/sbin/nginx | tee /home/dinko/exec-proj/log/nginx/function_trace_src_2.log
```

Followed by exercise script:
```sh
./exercise_nginx.sh
```