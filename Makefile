CC := gcc
CFLAG := -Wall -Wextra
CDBGF := -g -O0

VG := valgrind
VFLAG := --leak-check=full --show-leak-kinds=all --verbose

SRCDIR := ./src
LIBDIR := ./lib
OBJDIR := ./obj
BINDIR := ./bin

# beware of the order of obj files, `ld` handles each obj file with
# the order these file inputs and will not look back for "unsatisfied"
# symbols.
OBJS := cping.o cpaux.o
TEST := main.o

BIN := main

OBJDST := $(addprefix $(OBJDIR)/, $(OBJS) $(TEST))
BINDST := $(BINDIR)/$(BIN)

ifdef DEBUG
	CFLAG += $(CDBGF)
else
	CFLAG += -DNDEBUG
endif

# make directories
create_objdir:
	@mkdir -p $(OBJDIR)

create_bindir:
	@mkdir -p $(BINDIR)

build_test: $(OBJDST) create_bindir
	$(CC) $(CFLAG) $(OBJDST) -o $(BINDST)

$(OBJDIR)/%.o: $(SRCDIR)/%.c create_objdir
	$(CC) $(CFLAG) -c $< -o $@

check: build_test
	sudo $(VG) $(VFLAG) $(BINDST)

clean:
	rm -f $(OBJDST)

clean_all: clean
	rm -f $(BINDST)
