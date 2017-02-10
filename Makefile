default:
	gcc -Wall ./main.c -o ./ampere -lpcre -lsqlite3
	
debug:
	gcc -Wall ./main.c -o ./ampere -lpcre -lsqlite3 -DDEBUG_FLAG
	
v:
	gcc -O1 -Wall ./main.c -o ./ampere -lpcre -lsqlite3 -DDEBUG_FLAG
	strip ./ampere
	
nice:
	gcc -O1 -Wall ./main.c -o ./ampere -lpcre -lsqlite3
	strip ./ampere
