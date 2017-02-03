default:
	gcc -Wall ./main.c -o ./ampere -lpcre -lsqlite3 -Ddebug
	
nice:
	gcc -O3 -Wall ./main.c -o ./ampere -lpcre -lsqlite3
	strip ./ampere
