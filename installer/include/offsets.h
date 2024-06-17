#ifndef __OFFSETS_H__
#define __OFFSETS_H__
#pragma once

// 5.05
#define	XFAST_SYSCALL_addr              0x00001C0

// Names - Data
#define PRISON0_addr                    0x10986A0
#define ROOTVNODE_addr                  0x22C1A70
#define PMAP_STORE_addr                 0x22CB570
#define DT_HASH_SEGMENT_addr            0x0B5EF30

// Functions
#define pmap_protect_addr               0x02E3090
#define pmap_protect_p_addr             0x02E30D4

// Patches
// debug menu error
#define debug_menu_error_patch1         0x04F9048
#define debug_menu_error_patch2         0x04FA15C

// disable signature check
#define disable_signature_check_patch   0x06A2700

// enable debug RIFs
#define enable_debug_rifs_patch1        0x064B2B0
#define enable_debug_rifs_patch2        0x064B2D0

// allow sys_dynlib_dlsym in all processes
#define sys_dynlib_dlsym_patch          0x0237F3A

// sdk version spoof - enable all VR fws
#define sdk_version_patch               0x14A63F0

// enable debug log
#define enable_debug_log_patch          0x043612A

// enable uart output
#define enable_uart_patch               0x19ECEB0

#endif