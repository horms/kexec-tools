BIN_TO_HEX:= $(OBJDIR)/bin/bin-to-hex
$(BIN_TO_HEX): util/bin-to-hex.c
	mkdir -p $(@D)
	$(BUILD_CC) $(BUILD_CFLAGS) $< -o $@
