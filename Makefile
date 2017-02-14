default:
	gcc -O1 -Wall ./main.c -o ./ampere -lpcre -lsqlite3
	strip ./ampere
	
dev:
	gcc -Wall ./main.c -o ./ampere -lpcre -lsqlite3 -DDEBUG_FLAG
	
