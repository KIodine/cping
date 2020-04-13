CC := gcc
CFLAG := -Wall -Wextra
CDBGF := -g -O0

VG := valgrind
VFLAG := --leak-check=full --show-leak-kinds=all --verbose

INCDIR := ./include
SRCDIR := ./src
LIBDIR := ./lib
OBJDIR := ./obj
BINDIR := ./bin

CFLAG += -I$(INCDIR)
# beware of the order of obj files, `ld` handles each obj file with
# the order these file inputs and will not look back for "unsatisfied"
# symbols.
OBJS := cping.o cpaux.o icmp_srv.o tsutil.o addrutil.o
TEST := main.o

BIN := main
LIB := libcping

OBJDST := $(addprefix $(OBJDIR)/, $(OBJS) $(TEST))
BINDST := $(BINDIR)/$(BIN)

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

build_test: $(OBJDST) create_bindir
	$(CC) $(CFLAG) $(OBJDST) -o $(BINDST)

$(OBJDIR)/%.o: $(SRCDIR)/%.c create_objdir
	$(CC) $(CFLAG) -c $< -o $@

check: build_test
	sudo $(VG) $(VFLAG) $(BINDST)

static: $(OBJDST) create_libdir
	ar -rcs $(LIBDIR)/$(LIB).a $(OBJDST)

# Set target-specific var.
shared: CFLAG += -fPIC
shared: $(OBJDST) create_libdir
	$(CC) -shared $(CFLAG) $(OBJDST) -o $(LIBDIR)/$(LIB).so

clean:
	rm -f $(OBJDST)

clean_all: clean
	rm -f $(BINDST)
	rm -f $(LIBDIR)/*

# --- source file statistics ---
count_lines:
	@wc -lc \
	$(addprefix $(SRCDIR)/, $(subst .o,.c,$(OBJS))) \
	$(addprefix $(INCDIR)/, $(subst .o,.h,$(OBJS)))
