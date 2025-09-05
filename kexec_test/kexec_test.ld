ENTRY(_start)
SECTIONS
{
  . = 0x10000;
  .text : { *(.text .text.*) }

  /* Place the note after .text to avoid overlap */
  . = ALIGN(16);
  .note.gnu.property : { *(.note.gnu.property) }

  .rodata : { *(.rodata .rodata.*) }

  /* If you need bss fixed: */
  . = 0x12000;
  .bss : { *(.bss .bss.* COMMON) }
}
