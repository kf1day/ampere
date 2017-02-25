all:
	gcc -O1 -Wall -std=c99 ./main.c ./src/vmap.c -o ./ampere -lpcre -lsqlite3
	strip ./ampere
	
dev: bin/vmap-dev.o bin/main-dev.o
	gcc ./bin/vmap-dev.o ./bin/main-dev.o -o ./ampere-dev -lpcre -lsqlite3
	
bin/main-dev.o: src/main.c
	gcc -c -Wall -std=c99 ./src/main.c -o ./bin/main-dev.o -DDEBUG_FLAG
	
bin/vmap-dev.o: src/vmap.c
	gcc -c -Wall -std=c99 ./src/vmap.c -o ./bin/vmap-dev.o -DDEBUG_FLAG
	
clean:
	rm ./bin/*