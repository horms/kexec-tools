BIN_TO_HEX:= bin/bin-to-hex

$(BIN_TO_HEX): $(srcdir)/util/bin-to-hex.c
	@$(MKDIR) -p $(@D)
	$(LINK.o) -o $@ $^

$(BIN_TO_HEX): CC=$(BUILD_CC)
$(BIN_TO_HEX): CFLAGS=$(BUILD_CFLAGS)

clean += util/bin-to-hex.o $(BIN_TO_HEX)
