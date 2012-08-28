#Tetris in x86 assembly
#Copyright 2000,2001 dburr@ug.cs.usyd.edu.au, under the terms of the GPL
#
#Notes:
#Uses VT100 terminal codes to position the cursor and to draw coloured text.
#I also assume that this requires a > 2.0 Linux kernel which supports
#sys_newselect (also uses sys_write, sys_read, sys_nanosleep, sys_exit,
#sys_times and sys_ioctl).  I have only tested it with 2.0.x, 2.2.x and 2.4.x
#kernels.  I'm pretty sure that this will work with 386+ processors.
#
#Example Makefile:
#--start--
#NAME = tetris
#ENTRY = _tetris
#
#SYMS =  -defsym instructionsX=12
#SYMS += -defsym instructionsY=19
#SYMS += -defsym width=10
#SYMS += -defsym xoffset=3
#SYMS += -defsym height=16
#SYMS += -defsym yoffset=2
#SYMS += -defsym wait=50
#SYMS += -defsym scoredrop=2
#SYMS += -defsym scorelockin=3
#SYMS += -defsym scoreline=100
#SYMS += -defsym scoretetris=1000
#SYMS += -defsym speedup=10
#
#$(NAME): $(NAME).o
#   ld -s -o $@ -m elf_i386 $^ -e $(ENTRY)
#
#$(NAME).o: $(NAME).s
#   as -o $@ $^ $(SYMS)
#
#clean:
#   rm -f $(NAME).o $(NAME)
#--end--
#Explanation of the symbols which can be changed to suit personal taste:
#instructionsX, instructionsY: The offset of the instructions from the
#top, left hand corner of the screen.
#width, height: The dimensions of the playing area
#xoffset, yoffset: The offset of the playing area from the top, left hand
#corner of the screen.
#wait: Controls the speed of the game.  Lower number equals faster play.
#scoredrop: Number of points scored for 'dropping' a piece (with spacebar).
#scorelockin: Number of points scored for 'locking' a piece in.
#scoreline: Number of points scored for eliminating a line (for 1-3 lines)
#scoretetris: Number of points scored for a 'tetris' (ie eliminating 4 lines
#at once).
#speedup: The game will get twice as fast for every n lines.

.macro sys_newselect
    xor %eax, %eax #smaller than writing to %eax directly
    mov $142, %al #new sys_select
    xor %ebx, %ebx
    mov $1, %bl
    mov selectargs+4, %ecx
    xor %edx,%edx
    xor %esi,%esi
    mov $timeout,%edi
    int $0x80
.endm

.macro sys_nanosleep length
    xor %eax, %eax
    mov $162, %al #sys_nanosleep
    movl $0,-8(%esp) #seconds
    movl \length,-4(%esp) #nanoseconds
    lea -8(%esp),%ebx
    xor %ecx, %ecx
    int $0x80
.endm

.macro sys_exit
    xor %eax, %eax
    mov $1, %al #sys_exit
    xor %ebx,%ebx #with 0 status
    int $0x80
.endm

.macro sys_times
    xor %eax, %eax
    mov $43, %al #sys_times
    xor %ebx,%ebx #NULL
    int $0x80
.endm

.macro getterm
    push %ebp
    mov %esp,%ebp
    lea -60(%ebp),%edx
    mov $0x5401, %ecx #TCGETS
    call sys_ioctl 
.endm

.macro setterm
    leal -60(%ebp),%edx
    mov $0x5403, %ecx #TCSETSW
    call sys_ioctl
    pop %ebp
.endm

#Write the chars equivalent to 'source' into vt100_position
.macro twodigits source first second
    mov \source, %ax
    inc %ax
    movb $10, %bl
    divb %bl
    add $0x30,%al
    movb %al, vt100_position+\first
    add $0x30, %ah
    movb %ah, vt100_position+\second
.endm

#Named in honour of the ncurses function
.macro mvaddstr y x string length
    twodigits \y, 2, 3
    twodigits \x, 5, 6
    mov $vt100_position, %ecx
    xor %edx, %edx
    mov $8, %dl
    call sys_write
    mov \string, %ecx
    xor %edx, %edx
    mov \length, %dl
    call sys_write
.endm

#Mask of the bits for the n'th block
.macro bitMask n
    .if 4-\n
        shr $8-2*\n, %dx
    .endif
    and $0x303, %dx #Lower two bits of each
    mov yposition, %ax
    add %dl, %al
.endm

#Put the y location of the n'th block in %ax, x location in %bx
.macro screenoffset n
    bitMask \n
    mov xposition, %bx
    add %dh, %bl
.endm

#Make %bx the offset of the n'th block from the start of the screen array
#where %dx is the piece in question
.macro pieceoffset n
    bitMask \n
    imul $width, %ax
    add xposition, %ax
    shr $8, %dx
    add %dx, %ax
.endm

#Make real use of gas macros
.macro storeLoop from=1, to=4
    .if 4-\from
        movw (%esp), %dx
    .else
        pop %dx
    .endif
    pieceoffset \from
    movb %bl, (%eax,%ecx)
    .if \to-\from
        storeLoop "(\from+1)", \to
    .endif
.endm

.macro collisionLoop from=1, to=4
    .if 1-\from
        movw (%esp), %dx
    .endif
    pieceoffset \from
    movb (%ebx,%eax), %cl
    cmpb $0x30, %cl
    .if 4-\from
        jnz collisionTest_over
    .endif
    .if \to-\from
        collisionLoop "(\from+1)", \to
    .endif
.endm

.macro drawLoop from=1, to=4
    .if 1-\from
        movw (%esp), %cx
    .endif
    .if 4-\from
        mov 2(%esp), %dx
    .else
        pop %cx
        pop %dx
    .endif
    screenoffset \from
    call drawblock
    .if \to-\from
        drawLoop "(\from+1)", \to
    .endif
.endm

.data

quitstring:
    .ascii "'q' to quit, arrow keys to move"

scorestring:
    .ascii "Score: "

linestring:
    .ascii "Lines: "

namestring:
    .ascii "Daniel's Tetris"

blankstring:
    .ascii "  "

exitstring:
    .ascii "User exitted"
    
newline:
    .ascii "\n" #Also used after the previous string

loserstring:
    .ascii "Loser\n"

creditstring:
    .ascii "Tetris in 3k, by dburr@ug.cs.usyd.edu.au\n"

score:
    .hword 0

timeout:
    .long 0
    .long 1 #1 millisecond wait which checking stdin

selectargs:
    .long 1 #Max is 0, +1 = 1
    .long -1 #Overwrite with stack pointer
    .long 0 #No write
    .long 0 #No except
    .long timeout

vt100_position:
    .byte 0x1b
    .ascii "[12;13H"

vt100_colour: #The proper english way of spelling the word!
    .byte 0x1b
    .ascii "[44m"

vt100_clear:
    .byte 0x1b
    .ascii "[2J"

vt100_cursor:
    .byte 0x1b
    .ascii "[?25l"

yposition:
    .hword 0

xposition:
    .hword 2

sleepcount:
    .byte 0

shapeStarts:
    .byte 2, 3, 5, 7, 11, 15, 19

shapeIndex: #This data contains the positions of the blocks in each shape
#Each requires 16 bits: x1<<14|x2<<12|x3<<10|x4<<8|y1<<6|y2<<4|y3<<2|y4
    .hword 0b0000010100010110 #0<<14|0<<12|1<<10|1<<8|0<<6|1<<4|1<<2|2
    .hword 0b0100100100010001 #1<<14|0<<12|2<<10|1<<8|0<<6|1<<4|0<<2|1
    .hword 0b0000010100010100 #0<<14|0<<12|1<<10|1<<8|0<<6|1<<4|1<<2|0
    .hword 0b0000000000011011 #0<<14|0<<12|0<<10|0<<8|0<<6|1<<4|2<<2|3
    .hword 0b0001101100000000 #0<<14|1<<12|2<<10|3<<8|0<<6|0<<4|0<<2|0
    .hword 0b0001011000000101 #0<<14|1<<12|1<<10|2<<8|0<<6|0<<4|1<<2|1
    .hword 0b0100010000010110 #1<<14|0<<12|1<<10|0<<8|0<<6|1<<4|1<<2|2
    .hword 0b0001011001000101 #0<<14|1<<12|1<<10|2<<8|1<<6|0<<4|1<<2|1
    .hword 0b0100010100010110 #1<<14|0<<12|1<<10|1<<8|0<<6|1<<4|1<<2|2
    .hword 0b0001100100000001 #0<<14|1<<12|2<<10|1<<8|0<<6|0<<4|0<<2|1
    .hword 0b0000000100011001 #0<<14|0<<12|0<<10|1<<8|0<<6|1<<4|2<<2|1
    .hword 0b0001101000000001 #0<<14|1<<12|2<<10|2<<8|0<<6|0<<4|0<<2|1
    .hword 0b0001000000000110 #0<<14|1<<12|0<<10|0<<8|0<<6|0<<4|1<<2|2
    .hword 0b0000011000010101 #0<<14|0<<12|1<<10|2<<8|0<<6|1<<4|1<<2|1
    .hword 0b0101010000011010 #1<<14|1<<12|1<<10|0<<8|0<<6|1<<4|2<<2|2
    .hword 0b0001010100000110 #0<<14|1<<12|1<<10|1<<8|0<<6|0<<4|1<<2|2
    .hword 0b0001100000000001 #0<<14|1<<12|2<<10|0<<8|0<<6|0<<4|0<<2|1
    .hword 0b0000000100011010 #0<<14|0<<12|0<<10|1<<8|0<<6|1<<4|2<<2|2
    .hword 0b1000011000010101 #2<<14|0<<12|1<<10|2<<8|0<<6|1<<4|1<<2|1

linesgone:
    .hword 0 #number of lines eliminated so far in the game

currentwait:
    .byte wait #gets smaller as the game gets faster

.bss

buffer:
    .byte 0, 0 #for arrow keys we read two

rotation:
    .byte 0 #overwrite with a random rotation

blockType:
    .byte 0 #overwrite with a random block type

currentcolour:
    .byte 0 #overwrite with random colour

stringbuffer:
    .fill 5

screen:
    .fill width * height

lastrand:
    .long 0

.globl _tetris
.text

#Return a 4-bit number in %al that is no greater than %cl
rand:
    movl lastrand, %eax
    mov %eax, %ebx
    imul $1664525, %eax;
    add $1013904223, %eax
    shr $10, %eax
    xor %ebx, %eax
    movl %eax, lastrand
    andb $0x7, %al
    cmp %al, %cl
    jb rand
    ret

#Requires the string to write in %ecx, length in %edx
sys_write:
    xor %eax, %eax
    mov $4, %al #sys_write
    xor %ebx, %ebx
    mov $1, %bl #stdout
    int $0x80
    ret

#Requires the length to read in %edx
sys_read:
    xor %eax, %eax
    mov $3, %al #sys_read
    xor %ebx, %ebx #fd stdin
    mov $buffer, %ecx #buffer
    int $0x80
    ret

#Requires the number of the call in %ecx
sys_ioctl:
    xor %eax, %eax
    mov $54, %al #sys_ioctl
    xor %ebx, %ebx
    int $0x80
    ret

#Take the current entry from the shapeIndex and push it on the stack
coords:
    xor %edx, %edx
    xor %eax, %eax
    mov blockType, %al
    test %al, %al
    jz coords_noIndex
    mov $shapeStarts, %ebx
    dec %ebx
    mov (%eax, %ebx), %dl
coords_noIndex:
    add rotation, %dl
    shl $1, %dl #because each entry is 2 bytes
    pop %eax
    pushw shapeIndex(%edx)
    jmp *%eax

#There are 4 squares in the current piece.  Test the lines which these
#occupy to see if they are part of a complete line.  If so, remove, redraw
#Also adds to the score and speeds the game up if necessary
elimline:
    mov yposition, %dx
    add $4, %dl
    xor %eax, %eax
    mov yposition, %al #%al contains the ypositions to test
    xor %dh, %dh #number of lines eliminated
    cmpb $height-1, %dl
    jl elimline_skip
    mov $height-1, %dl #%dl contains one more than the last value to test
elimline_skip:
    xor %ebx, %ebx
    mov $width, %bl
    imul %eax, %ebx
    add $screen, %ebx #ebx contains the start of the line
    xor %ecx, %ecx
elimline_test:
    inc %cl #%ecx contains the x position to test
    cmpb $0x30, (%ecx, %ebx) #test this for each position in line
    je elimline_linedone #ie: don't eliminate this line
    cmpb $width-2, %cl
    jne elimline_test
    inc %dh
    add $width, %ebx
elimline_loop:
    dec %ebx
    movb -width(%ebx), %cl
    movb %cl, (%ebx)
    cmp $screen+width, %ebx
    jne elimline_loop
elimline_linedone:
    inc %al
    cmp %al, %dl
    jne elimline_skip
    mov %dx, %cx #for testing linesgone later
    cmpb $4, %dh
    je elimline_tetris
    shr $8, %dx

    imul $scoreline, %dx
    addw %dx, score
    jmp elimline_finished
elimline_tetris:
    addw $scoretetris, score
elimline_finished:
    shr $8, %cx
    movw linesgone, %ax
    mov $speedup, %bl
    div %bl
    mov %al, %dl
    addw %cx, linesgone
    movw linesgone, %ax
    div %bl
    cmp %al, %dl
    je elimline_samespeed
    shrb $1, currentwait
elimline_samespeed:
    call redraw
    ret

#Write the block into the screen array at xposition,yposition
storePiece:
    addw $scorelockin, score
    decw yposition
    mov yposition, %ax
    test %ax, %ax
    jz gameover

    call coords
    xor %eax, %eax
    mov currentcolour, %bl
    mov $screen, %ecx
    storeLoop

    call elimline
    mov currentcolour, %cl
    movw $0, yposition
    movw $2, xposition
    movb $0, sleepcount
    ret

#Draw the current blockType at xposition,yposition (offset from xoffset,
#yoffset).  Will be coloured depending on %cl. Update score
drawShape:
    call coords
    push %cx
    drawLoop
    movb $0x30, vt100_colour+3
    mov $vt100_colour, %ecx
    xor %edx, %edx
    mov $5, %dl
    call sys_write
    mvaddstr $instructionsY+2, $instructionsX, $scorestring, $7
    mov score, %ax
    call numbertostring
    call sys_write
    mvaddstr $instructionsY+3, $instructionsX, $linestring, $7
    mov linesgone, %ax
    call numbertostring
    call sys_write
    ret

#Return the string location in %ecx, length in %edx, requires number in %ax
numbertostring:
    mov $10, %bx
    mov $stringbuffer+5, %ecx
numbertostring_loop:
    dec %ecx
    xor %dx,%dx
    div %bx
    add $0x30, %dx
    movb %dl, (%ecx)
    test %ax,%ax
    jnz numbertostring_loop
    mov %ecx,%ebx
    sub $stringbuffer, %ebx
    xor %edx, %edx
    mov $5, %dl
    sub %ebx, %edx
    ret

#Requires the y coord in %ax, x coord in %bx, val to colour in %cl
drawblock:
    add $xoffset,%bx
    add $yoffset,%ax
    push %ax
    push %bx
    movb %cl, vt100_colour+3
    mov $vt100_colour, %ecx
    xor %edx, %edx
    mov $5, %dl
    call sys_write
    pop %cx
    pop %ax
    shl $1, %cx
    mvaddstr %ax, %cx, $blankstring, $2
    ret

#Redraw the playing area (doesn't update score)
redraw:
    xor %ax, %ax #y
redraw_outer:
        xor %ebx, %ebx #x
redraw_inner:
        push %ebx
        push %ax

        xor %ecx, %ecx
        mov $width, %cl
        imul %eax, %ecx
        mov screen(%ebx, %ecx), %cx

        call drawblock

        pop %ax
        pop %ebx

        inc %bl
        cmpb $width, %bl
        jl redraw_inner
    inc %ax
    cmpb $height, %al
    jl redraw_outer
    ret

gameover:
    mov currentcolour, %cl
    call drawShape
    movw $0x3030, vt100_colour+2
    mov $vt100_colour, %ecx
    xor %edx, %edx
    mov $5, %dl
    call sys_write
    movb $'h',vt100_cursor+5
    mov $vt100_cursor, %ecx
    xor %edx, %edx
    mov $6, %dl
    call sys_write
    cmpb $'q',buffer
    jne gameover_loser
    mvaddstr $instructionsY+4, $0, $exitstring, $13
    jmp gameover_quit
gameover_loser:
    mvaddstr $instructionsY+4, $0, $loserstring, $6
gameover_quit:
    mov $scorestring, %ecx
    xor %edx, %edx
    mov $7, %dl
    call sys_write
    mov score, %ax
    call numbertostring
    call sys_write
    mov $newline, %ecx
    xor %edx, %edx
    mov $1, %dl
    call sys_write
    mov $creditstring, %ecx
    xor %edx, %edx
    mov $41, %dl
    call sys_write
    getterm
    or $10,-48(%ebp) #c_lflag |= (ICANON|ECHO)
    setterm
    sys_exit

#Test the shape for any collision.  If collision, then the zero flag will
#NOT be set
collisionTest:
    call coords
    xor %eax, %eax
    mov $screen, %ebx
    collisionLoop
collisionTest_over:
    pop %dx
    ret

#Writes the number of rotations of blockType into %cl
numberrots:
    xor %ebx, %ebx
    mov blockType, %bl
    test %bl,%bl
    jz numberrots_zeroshape
    add $shapeStarts, %ebx
    mov (%ebx), %cl
    sub -1(%ebx), %cl
    jmp numberrots_done
numberrots_zeroshape:
    mov shapeStarts, %cl
numberrots_done:
    ret

_tetris:
    getterm
    andb $245,-48(%ebp) #c_lflags &= ~(ICANON|ECHO)
    setterm

    sys_times
    mov %eax, lastrand #seed the randomizer

    mov $vt100_clear, %ecx
    xor %edx, %edx
    mov $4, %dl
    call sys_write
    mov $vt100_cursor, %ecx
    xor %edx, %edx
    mov $6, %dl
    call sys_write
    mov $vt100_colour, %ecx
    xor %edx, %edx
    mov $5, %dl
    call sys_write
    mvaddstr $instructionsY, $instructionsX, $namestring, $15
    mvaddstr $instructionsY+1, $instructionsX, $quitstring, $31

    xor %al,%al
    mov $screen,%ebx
tetris_yloop:
    movb $0x31, (%ebx) #red for the playing arena
    movb $0x31, width-1(%ebx)
    xor %ecx, %ecx
    mov $1,%cl
tetris_yloop_inner:
        movb $0x30,(%ebx,%ecx) #init to black
        inc %cl
        cmpb $width-1,%cl
        jl tetris_yloop_inner

    add $width,%ebx
    inc %al
    cmpb $height-1,%al
    jl tetris_yloop

    xor %ebx, %ebx
    mov $width,%bl
    imul $height-1,%ebx
    add $screen,%ebx
    xor %eax,%eax
tetris_xloop:
    movb $0x31,(%eax,%ebx)
    inc %al
    cmpb $width,%al
    jl tetris_xloop

    call redraw

playgame:
    mov $6, %cl #7 shapes
    call rand
    movb %al, blockType
    call numberrots
    dec %cl
    call rand
    movb %al, rotation
    mov $6, %cl
    call rand
    add $0x31, %al
    mov %al, currentcolour
    call collisionTest
    jnz gameover

playgame_keyloop:
    sys_nanosleep $250000
    push %ebp
        xor %eax,%eax
        mov %esp,%ebp
        sub $252,%esp
        bts %eax,-128(%ebp)
        lea -128(%ebp),%eax
    mov %eax,selectargs+4
    sys_newselect
        movl %ebp,%esp
    pop %ebp

    test %eax,%eax
    jnz playgame_checkkey
playgame_keychecked:
    movb currentcolour, %cl
    call drawShape
    incb sleepcount
    movb currentwait, %cl
    cmpb %cl,sleepcount
    jne playgame_keyloop
    movb $0,sleepcount
    mov $0x30, %cl #black to overwrite
    call drawShape
    incw yposition
    call collisionTest
    jz playgame_keychecked
    call storePiece
    jmp playgame
playgame_checkkey:
    mov $0x30, %cl
    call drawShape
    xor %edx, %edx
    mov $1, %dl
    call sys_read
    cmpb $'q',buffer
    je gameover
    cmpb $' ',buffer
    jne playgame_checkarrow
playgame_droploop:
    incw yposition
    call collisionTest
    jz playgame_droploop
    call storePiece
    addw $scoredrop, score
    jmp playgame
playgame_checkarrow:
    cmpb $0x1b,buffer #check for arrow key
    jne playgame_keychecked
    xor %edx, %edx
    mov $2, %dl
    call sys_read
#use a jump table later
    movb buffer+1,%al
    cmpb $'D',%al #Left arrow
    jne playgame_nextkey
    decw xposition
    call collisionTest
    jz playgame_nextkey
    incw xposition
playgame_nextkey:
    cmpb $'C',%al #Right Arrow
    jne playgame_nextkey2
    incw xposition
    call collisionTest
    jz playgame_nextkey2
    decw xposition
playgame_nextkey2:
    cmpb $'B',%al #Down Arrow
    jne playgame_nextkey3
    incw yposition
    call collisionTest
    jz playgame_nextkey3
    decw yposition
playgame_nextkey3:
    cmpb $'A',%al #Up Arrow
    jne playgame_keychecked
    xor %ah, %ah
    mov rotation, %al
    push %ax
    inc %ax
    call numberrots
    divb %cl
    movb %ah, rotation
    call collisionTest
    jz playgame_keychecked
    pop %cx
    mov %cl, rotation
    jmp playgame_keychecked
