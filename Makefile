
CROSS_COMPILE = arm-none-eabi-

# Use our cross-compile prefix to set up our basic cross compile environment.
CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy

CFLAGS = \
	-mtune=arm7tdmi \
	-mlittle-endian \
	-fno-stack-protector \
	-fno-common \
	-fno-builtin \
	-ffreestanding \
	-std=gnu99 \
	-Werror \
	-Wall \
	-Wno-error=unused-function \
	-fomit-frame-pointer \
	-g \
	-Os \

LDFLAGS =

all: intermezzo.bin

# The start of the BPMP IRAM.
START_OF_IRAM := 0x40000000

# The address to which Intermezzo is to be loaded by the payload launcher.
INTERMEZZO_ADDRESS := 0x4001F000

# The address we want the final payload to be located at.
RELOCATION_TARGET  := 0x40010000

# The addrss and length of the data loaded by f-g.
LOAD_BLOCK_START   := 0x40020000
LOAD_BLOCK_LENGTH  := 0x20000

# Provide the definitions used in the intermezzo stub.
DEFINES := \
	-DSTART_OF_IRAM=$(START_OF_IRAM) \
	-DRELOCATION_TARGET=$(RELOCATION_TARGET) \
	-DLOAD_BLOCK_START=$(LOAD_BLOCK_START) \
	-DLOAD_BLOCK_LENGTH=$(LOAD_BLOCK_LENGTH) \

intermezzo.elf: intermezzo.o
	$(LD) -T intermezzo.lds --defsym LOAD_ADDR=$(INTERMEZZO_ADDRESS) $(LDFLAGS) $^ -o $@

intermezzo.o: intermezzo.S
	$(CC) $(CFLAGS32) $(DEFINES) $< -c -o $@

%.bin: %.elf
	$(OBJCOPY) -v -O binary $< $@

clean:
	rm -f *.o *.elf *.bin

.PHONY: all clean
