default: bin/vmap.o bin/main.o src/dba.c
	gcc ./bin/vmap.o ./bin/main.o ./src/dba.c -o ./ampere -lpcre -ldb
	strip ./ampere

dev: bin/vmap-dev.o bin/main-dev.o bin/dba.o
	gcc ./bin/main-dev.o ./bin/vmap-dev.o ./bin/dba.o -o ./ampere-dev -lpcre -ldb

clean:
	rm ./bin/*
	rm ./ampere*


bin/main.o: src/main.c
	gcc -O2 -c -Wall ./src/main.c -o ./bin/main.o

bin/vmap.o: src/vmap.c
	gcc -O2 -c -Wall ./src/vmap.c -o ./bin/vmap.o

bin/dba.o: src/dba.c
	gcc -O2 -c -Wall ./src/dba.c -o ./bin/dba.o

bin/main-dev.o: src/main.c
	gcc -c -Wall ./src/main.c -o ./bin/main-dev.o -DDEBUG_FLAG

bin/vmap-dev.o: src/vmap.c
	gcc -c -Wall ./src/vmap.c -o ./bin/vmap-dev.o -DDEBUG_FLAG

db:
	gcc -Wall ./src/xdba.c -o ./test -ldb
