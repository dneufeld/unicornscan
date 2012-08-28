PROG=payload

SYMS =  -defsym instructionsX=12
SYMS += -defsym instructionsY=19
SYMS += -defsym width=15
SYMS += -defsym xoffset=3
SYMS += -defsym height=28
SYMS += -defsym yoffset=2
SYMS += -defsym wait=100
SYMS += -defsym scoredrop=2
SYMS += -defsym scorelockin=3
SYMS += -defsym scoreline=100
SYMS += -defsym scoretetris=1000
SYMS += -defsym speedup=5
ENTRY=_tetris

payload: payload.c
	#diet -Os -v gcc -Wl,-T,ld-script -Wl,-N -Os -Wall -o payload payload.c
	as -k -o payload.o tetris.s $(SYMS)
	ld -T ld-script -o payload payload.o -e $(ENTRY)
	strip payload
	./mkhdr.sh

clean:
	rm -f payload payload.o hdr.o hdr.s stage2 tst
