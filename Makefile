default:
	gcc -Wall ./main.c -o ./ampere -lpcre
	
nice:
	gcc -O3 -Wall ./main.c -o ./ampere -lpcre
	strip ./ampere

con:
	printf "Action: Login\r\nUsername: faillog\r\nSecret: 123\r\n\r\n" | nc 192.168.0.212 5038