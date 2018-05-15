OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

ENTRY(_start)

PHDRS
{
	header_seg PT_LOAD;
	code_seg PT_LOAD;
	rdata_seg PT_LOAD;
	data_seg PT_LOAD;
	bss_seg PT_LOAD;
	bad_rdata_seg PT_LOAD;
	bad_data_seg PT_LOAD;
	bad_bss_seg PT_LOAD;
}

SECTIONS
{
	. = 0;
	.payload_header : { *(.payload_header) } : header_seg
	.payload_code : { *(.payload_code) } : code_seg
	.payload_data : { *(.payload_rdata .rodata*) } : rdata_seg
	.payload_data : { *(.payload_data) } : data_seg
	.payload_bss  : { *(.payload_bss) } : bss_seg
	. = 0x100000;
	.data : { *(.data) } : bad_data_seg
	.bss  : { *(.bss) } : bad_bss_seg
	/DISCARD/ : { *(*) }
}
