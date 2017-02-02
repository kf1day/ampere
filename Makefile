default:
	gcc -Wall ./main.c -o ./ampere -lpcre -Ddebug
	
nice:
	gcc -O3 -Wall ./main.c -o ./ampere -lpcre
	strip ./ampere
