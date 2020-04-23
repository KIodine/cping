CC := gcc
CFLAG := -Wall -Wextra
CDBGF := -g -O0

VG := valgrind
VFLAG := --leak-check=full --show-leak-kinds=all --verbose

INCDIR := ./include
SRCDIR := ./src
TSTDIR := ./test
LIBDIR := ./lib
OBJDIR := ./obj
BINDIR := ./bin

CFLAG += -I$(INCDIR)
# beware of the order of obj files, `ld` handles each obj file with
# the order these file inputs and will not look back for "unsatisfied"
# symbols.
OBJS := \
	cping.o cpaux.o cp_sock.o icmp_srv.o \
	tsutil.o addrutil.o
TEST := main.o

BIN := main
LIB := libcping

OBJDST := $(addprefix $(OBJDIR)/, $(OBJS))
BINDST := $(BINDIR)/$(BIN)
TSTDST := $(OBJDIR)/$(TEST)

ifdef DEBUG
	CFLAG += $(CDBGF)
else
	CFLAG += -DNDEBUG -O1
endif

# make directories
create_objdir:
	@mkdir -p $(OBJDIR)

create_bindir:
	@mkdir -p $(BINDIR)

create_libdir:
	@mkdir -p $(LIBDIR)

build_test: $(OBJDST) create_bindir static testmain
	$(CC) $(CFLAG) -L./$(LIBDIR) -lcping -o $(BINDST) \
	$(OBJDST) $(TSTDST)

$(OBJDIR)/%.o: $(SRCDIR)/%.c create_objdir
	$(CC) $(CFLAG) -c $< -o $@

testmain:
	$(CC) $(CFLAG) -c $(TSTDIR)/main.c -o $(TSTDST)

check: build_test
	sudo $(VG) $(VFLAG) $(BINDST)

static: $(OBJDST) create_libdir
	ar -rcs $(LIBDIR)/$(LIB).a $(OBJDST)

# Set target-specific var.
shared: CFLAG += -fPIC
shared: $(OBJDST) create_libdir
	$(CC) -shared $(CFLAG) $(OBJDST) -o $(LIBDIR)/$(LIB).so

clean:
	rm -f $(OBJDST) $(TSTDST)

clean_all: clean
	rm -f $(BINDST)
	rm -f $(LIBDIR)/*

# --- source file statistics ---
count_lines:
	@find include/* src/* test/* | xargs wc -lc
