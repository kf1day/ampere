default: bin/main.o bin/vmap.o bin/dba.o
	gcc ./bin/main.o ./bin/vmap.o ./bin/dba.o -o ./ampere -lpcre -ldb
	strip ./ampere

dev: bin/main-dev.o bin/vmap-dev.o bin/dba.o
	gcc ./bin/vmap-dev.o ./bin/main-dev.o ./bin/dba.o -o ./ampere-dev -lpcre -ldb

clean:
	rm -f ./bin/* ./ampere ./ampere-dev


bin/main.o: src/main.c
	gcc -O1 -c -Wall ./src/main.c -o ./bin/main.o

bin/vmap.o: src/vmap.c
	gcc -O1 -c -Wall ./src/vmap.c -o ./bin/vmap.o

bin/dba.o: src/dba.c
	gcc -O1 -c -Wall ./src/dba.c -o ./bin/dba.o



bin/main-dev.o: src/main.c
	gcc -g -c -Wall ./src/main.c -o ./bin/main-dev.o -DDEBUG_FLAG

bin/vmap-dev.o: src/vmap.c
	gcc -g -c -Wall ./src/vmap.c -o ./bin/vmap-dev.o

