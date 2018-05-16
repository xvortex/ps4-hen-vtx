#include "ps4.h"
#include "defines.h"
#include "debug.h"

#define kernel_printf(format, ...) (void)0

#define PS4_UPDATE_FULL_PATH "/update/PS4UPDATE.PUP"
#define PS4_UPDATE_TEMP_PATH "/update/PS4UPDATE.PUP.net.temp"

#define	KERN_XFAST_SYSCALL	0x1C0		// 5.01
#define KERN_PRISON_0		0x10986A0
#define KERN_ROOTVNODE		0x22C19F0

#define KERN_PMAP_PROTECT	0x2E2D00
#define KERN_PMAP_PROTECT_P	0x2E2D44
#define KERN_PMAP_STORE		0x22CB4F0

#define KERN_REGMGR_SETINT	0x4F8940

#define DT_HASH_SEGMENT		0xB5EE20

extern char kpayload[];
unsigned kpayload_size;

int do_patch();

int install_payload(struct thread *td, struct install_payload_args* args)
{
  uint64_t flags, cr0;

  uint8_t* kernel_base = (uint8_t*)(__readmsr(0xC0000082) - KERN_XFAST_SYSCALL);

  void (*pmap_protect)(void * pmap, uint64_t sva, uint64_t eva, uint8_t pr) = (void *)(kernel_base + KERN_PMAP_PROTECT);
  void *kernel_pmap_store = (void *)(kernel_base + KERN_PMAP_STORE);

  kernel_printf("\n\n\n\npayload_installer: starting\n");
  kernel_printf("payload_installer: kernel base=%lx\n", kernel_base);

  if (!args->payload_info)
  {
    kernel_printf("payload_installer: bad payload info\n");
    return -1;
  }

  uint8_t* payload_data = args->payload_info->buffer;
  size_t payload_size = args->payload_info->size;
  struct payload_header* payload_header = (struct payload_header*)payload_data;

  if (!payload_data ||
      payload_size < sizeof(payload_header) ||
      payload_header->signature != 0x5041594C4F414430ull)
  {
    kernel_printf("payload_installer: bad payload data\n");
    return -2;
  }

  uint8_t* payload_buffer = (uint8_t*)&kernel_base[DT_HASH_SEGMENT];

  kernel_printf("payload_installer: installing...\n");
  kernel_printf("payload_installer: target=%lx\n", payload_buffer);
  kernel_printf("payload_installer: payload=%lx,%lu\n",
    payload_data, payload_size);

  cr0 = readCr0();
  writeCr0(cr0 & ~X86_CR0_WP);

  kernel_printf("payload_installer: memset\n");
  memset(payload_buffer, 0, PAGE_SIZE);

  kernel_printf("payload_installer: memcpy\n");
  memcpy(payload_buffer, payload_data, payload_size);

  kernel_printf("payload_installer: remap\n");
  uint64_t sss = ((uint64_t)payload_buffer) & ~(uint64_t)(PAGE_SIZE-1);
  uint64_t eee = ((uint64_t)payload_buffer + payload_size + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE-1);
  kernel_base[KERN_PMAP_PROTECT_P] = 0xEB;
  pmap_protect(kernel_pmap_store, sss, eee, 7);
  kernel_base[KERN_PMAP_PROTECT_P] = 0x75;

  kernel_printf("payload_installer: patching payload pointers\n");
  if (payload_header->real_info_offset != 0 &&
    payload_header->real_info_offset + sizeof(struct real_info) <= payload_size)
  {
    struct real_info* real_info =
      (struct real_info*)(&payload_data[payload_header->real_info_offset]);
    for (
      ; real_info->payload_offset != 0 && real_info->kernel_offset != 0
      ; ++real_info)
    {
      uint64_t* payload_target =
        (uint64_t*)(&payload_buffer[real_info->payload_offset]);
      void* kernel_target = &kernel_base[real_info->kernel_offset];
      *payload_target = (uint64_t)kernel_target;
      kernel_printf("  %x(%lx) = %x(%lx)\n",
        real_info->payload_offset, payload_target,
        real_info->kernel_offset, kernel_target);
    }
  }

  flags = intr_disable();

  kernel_printf("payload_installer: patching calls\n");
  if (payload_header->disp_info_offset != 0 &&
    payload_header->disp_info_offset + sizeof(struct disp_info) <= payload_size)
  {
    struct disp_info* disp_info =
      (struct disp_info*)(&payload_data[payload_header->disp_info_offset]);
    for (
      ; disp_info->call_offset != 0 && disp_info->payload_offset != 0
      ; ++disp_info)
    {
      uint8_t* call_target = &kernel_base[disp_info->call_offset];
      uint8_t* payload_target = &payload_buffer[disp_info->payload_offset];

      int32_t new_disp = (int32_t)(payload_target - &call_target[5]);

      kernel_printf("  %lx(%lx)\n",
        disp_info->call_offset + 1, &call_target[1]);
      kernel_printf("    %lx(%lx) -> %lx(%lx) = %d\n",
        disp_info->call_offset + 5, &call_target[5],
        disp_info->payload_offset, payload_target,
        new_disp);

      *((int32_t*)&call_target[1]) = new_disp;
    }
  }

  intr_restore(flags);
  writeCr0(cr0);

  if (payload_header->entrypoint_offset != 0 &&
    payload_header->entrypoint_offset < payload_size)
  {
    kernel_printf("payload_installer: entrypoint\n");
    void (*payload_entrypoint)();
    *((void**)&payload_entrypoint) =
      (void*)(&payload_buffer[payload_header->entrypoint_offset]);
    payload_entrypoint();
  }

  kernel_printf("payload_installer: done\n");
  return 0;
}

int kernel_payload(struct thread *td, struct kernel_payload_args* args)
{
  struct ucred* cred;
  struct filedesc* fd;

  uint64_t (*sceRegMgrSetInt)(uint32_t regId, int value, int unk1, int unk2, int unk3);

  fd = td->td_proc->p_fd;
  cred = td->td_proc->p_ucred;

  void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_XFAST_SYSCALL];
  uint8_t* kernel_ptr = (uint8_t*)kernel_base;
  void** got_prison0 =   (void**)&kernel_ptr[KERN_PRISON_0];
  void** got_rootvnode = (void**)&kernel_ptr[KERN_ROOTVNODE];
  *(void**)(&sceRegMgrSetInt) = &kernel_ptr[KERN_REGMGR_SETINT];

  cred->cr_uid = 0;
  cred->cr_ruid = 0;
  cred->cr_rgid = 0;
  cred->cr_groups[0] = 0;

  cred->cr_prison = *got_prison0;
  fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

  // escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
  void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
  // sceSblACMgrIsSystemUcred
  uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
  *sonyCred = 0xffffffffffffffff;
	
  // sceSblACMgrGetDeviceAccessType
  uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
  *sceProcType = 0x3801000000000013; // Max access
	
  // sceSblACMgrHasSceProcessCapability
  uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
  *sceProcCap = 0xffffffffffffffff; // Sce Process

  // enable permanent Internet Web Browser
  sceRegMgrSetInt(0x3C040000, 0, 0, 0, 0);
  
  // Disable write protection
  uint64_t cr0 = readCr0();
  writeCr0(cr0 & ~X86_CR0_WP);

  // debug settings patches 5.01
  *(char *)(kernel_base + 0x1CD0686) |= 0x14;
  *(char *)(kernel_base + 0x1CD06A9) |= 3;
  *(char *)(kernel_base + 0x1CD06AA) |= 1;
  *(char *)(kernel_base + 0x1CD06C8) |= 1;

  // debug menu error patches 5.01
  *(uint32_t *)(kernel_base + 0x4F8C78) = 0;
  *(uint32_t *)(kernel_base + 0x4F9D8C) = 0;

  // target_id patches 5.01
  *(uint16_t *)(kernel_base + 0x1CD068C) = 0x8101;
  *(uint16_t *)(kernel_base + 0x236B7FC) = 0x8101;

  // flatz disable pfs signature check 5.01
  *(uint32_t *)(kernel_base + 0x6A2320) = 0x90C3C031;

  // flatz enable debug RIFs 5.01
  *(uint32_t *)(kernel_base + 0x64AED0) = 0x90C301B0;
  *(uint32_t *)(kernel_base + 0x64AEF0) = 0x90C301B0;

  // Restore write protection
  writeCr0(cr0);

  return 0;
}

static inline void patch_update(void)
{
  unlink(PS4_UPDATE_FULL_PATH);
  unlink(PS4_UPDATE_TEMP_PATH);

  mkdir(PS4_UPDATE_FULL_PATH, 0777);
  mkdir(PS4_UPDATE_TEMP_PATH, 0777);
}

int _main(struct thread *td) {
  int result;

  initKernel();	
  initLibc();

#ifdef DEBUG_SOCKET
  initNetwork();
  initDebugSocket();
#endif

  printfsocket("Starting...\n");

  result = kexec(&kernel_payload, NULL);
  printfsocket("kernel_payload: %d\n", result);
  if (result) goto exit;

  patch_update();

  result = errno = do_patch();
  printfsocket("do_patch: %d\n", result);
  if (result) goto exit;

  struct payload_info payload_info;
  payload_info.buffer = (uint8_t *)kpayload;
  payload_info.size = (size_t)kpayload_size;

  errno = 0;

  result = kexec(&install_payload, &payload_info);
  result = !result ? 0 : errno;
  printfsocket("install_payload: %d\n", result);
  if (result) goto exit;

  initSysUtil();
  notify("Welcome to PS4HEN v"VERSION);

exit:
  printfsocket("Done.\n");

#ifdef DEBUG_SOCKET
  closeDebugSocket();
#endif

  return !result ? 0 : errno;
}
