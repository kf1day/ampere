default:
	gcc -Wall ./main.c -o ./ampere -lpcre -lsqlite3
	
debug:
	gcc -Wall ./main.c -o ./ampere -lpcre -lsqlite3 -DDEBUG_FLAG
	
nice:
	gcc -O3 -Wall ./main.c -o ./ampere -lpcre -lsqlite3
	strip ./ampere
