all: testattack myids

testattack: testattack.c
	gcc testattack.c -o testattack
myids: myids.c
	gcc myids.c -lpcap -o myids
clean:
	@rm testattack myids
