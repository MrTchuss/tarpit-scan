#Define flags - can be overriden/added in config.mk
CC=gcc
INCLUDE=include
CFLAGS=-Wall
#You may want to stip out lib and/or ansi compliance
LDFLAGS=
LDLIBS=

#Define directories
SRCDIR=src
DISTDIR=dist
OBJDIR=obj
DEPDIR=deps
#VPATH=$(SRCDIR)

#Automatically find sources
SOURCES=$(wildcard $(SRCDIR)/*.c)
OBJECTS=$(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))

#Subdirectories containing code that can compile with their own Makefile
SUBDIRS=

#Look for user customistaion : BINNAME, SUBDIRS, etc.
include config.mk #define BINNAME in there

ifndef BINNAME
   $(error Variable BINNAME is not defined in config.mk)
endif

#Add -I in front of INCLUDE directory
INCLUDES=$(foreach dir,$(INCLUDE),-I$(dir) )

#BIN is located in DISTDIR
BIN=$(DISTDIR)/$(BINNAME)

.PHONY: all clean options

all: $(DISTDIR) $(SUBDIRS) $(BIN)

#Take all objects ($^) and build an executable
$(BIN): $(OBJECTS)
	@echo CC -o $@
	@$(CC) $(INCLUDES) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# Take dependencies contained in .d into account
-include $(addprefix $(DEPDIR)/, $(notdir $(OBJECTS:.o=.d)))

#Build relocatable object from a single ($<) C source file
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR) $(DEPDIR)
	@echo CC -o $@
	@$(CC) $(INCLUDES) -c $(CFLAGS) $< -o $@ 
# Get dependencies
	@$(CC) $(INCLUDES) -MM -MT $@ $< > $(DEPDIR)/$*.d
# Add Makefile to the list of dependencies
	@/bin/sed -i '/\\$$/! s/\(.*\)/\1 Makefile config.mk/g' $(DEPDIR)/$*.d

$(SUBDIRS):
	@for dir in $(SUBDIRS); do \
	   $(MAKE) -C $$dir; \
	done

$(DISTDIR) $(OBJDIR) $(DEPDIR):
	@mkdir $@

options:
	@echo $(BIN) build options:
	@echo "   CC      = $(CC)"
	@echo "   INCLUDE = $(INCLUDE)"
	@echo "   CFLAGS  = $(CFLAGS)"
	@echo "   LDFLAGS = $(LDFLAGS)"
	@echo "   LDLIBS  = $(LDLIBS)"

clean:
	@echo cleaning
	@rm -rf $(DEPDIR)/*.d $(OBJDIR)/*o $(BIN)
	@for dir in $(SUBDIRS); do \
	   $(MAKE) -C $$dir clean; \
	done

mrproper: clean
	@rm -rf $(DISTDIR) $(OBJDIR) $(DEPDIR)
