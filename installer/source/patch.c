#include <assert.h>

#include "ps4.h"
#include "defines.h"
#include "debug.h"

int find_process(const char* target)
{
  int pid;
  int mib[3] = {1, 14, 0};
  size_t size, count;
  char* data;
  char* proc;

  if (sysctl(mib, 3, NULL, &size, NULL, 0) < 0)
  {
    return -1;
  }

  if (size == 0)
  {
    return -2;
  }

  data = (char*)malloc(size);
  if (data == NULL)
  {
    return -3;
  }

  if (sysctl(mib, 3, data, &size, NULL, 0) < 0)
  {
    free(data);
    return -4;
  }

  count = size / 0x448;
  proc = data;
  pid = -1;
  while (count != 0)
  {
    char* name = &proc[0x1BF];
    if (strncmp(name, target, strlen(target)) == 0)
    {
      pid = *(int*)(&proc[0x48]);
      break;
    }
    proc += 0x448;
    count--;
  }

  free(data);
  return pid;
}

int get_code_info(int pid, uint64_t* paddress, uint64_t* psize, uint64_t known_size)
{
  int mib[4] = {1, 14, 32, pid};
  size_t size, count;
  char* data;
  char* entry;

  if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0)
  {
    return -1;
  }

  if (size == 0)
  {
    return -2;
  }

  data = (char*)malloc(size);
  if (data == NULL)
  {
    return -3;
  }

  if (sysctl(mib, 4, data, &size, NULL, 0) < 0)
  {
    free(data);
    return -4;
  }

  int struct_size = *(int*)data;
  count = size / struct_size;
  entry = data;

  int found = 0;
  while (count != 0)
  {
    int type = *(int*)(&entry[0x4]);
    uint64_t start_addr = *(uint64_t*)(&entry[0x8]);
    uint64_t end_addr = *(uint64_t*)(&entry[0x10]);
    uint64_t code_size = end_addr - start_addr;
    uint32_t prot = *(uint32_t*)(&entry[0x38]);

    printfsocket("%d 0x%llx 0x%llx (0x%llx) %x\n", type, start_addr, end_addr, code_size, prot);

    if (type == 255 && prot == 5 && code_size == known_size)
    {
      *paddress = start_addr;
      *psize = (end_addr - start_addr);
      found = 1;
      break;
    }

    entry += struct_size;
    count--;
  }

  free(data);
  return !found ? -5 : 0;
}

typedef struct _patch_info
{
  const char* name;
  uint32_t address;
  const char* data;
  uint32_t size;
}
patch_info;

int apply_patches(int pid, uint64_t known_size, const patch_info* patches)
{
  uint64_t code_address, code_size;
  int result = get_code_info(pid, &code_address, &code_size, known_size);
  if (result < 0)
  {
    printfsocket("Failed to get code info for %d: %d\n", pid, result);
    return -1;
  }

  char proc_path[64];
  sprintf(proc_path, "/mnt/proc/%d/mem", pid);

  int fd = open(proc_path, O_RDWR, 0);
  if (fd < 0)
  {
    printfsocket("Failed to open %s!\n", proc_path);
    return -2;
  }

  printfsocket("Opened process memory...\n");
  for (int i = 0; patches[i].data != NULL; i++)
  {
    lseek(fd, code_address + patches[i].address, SEEK_SET);
    result = write(fd, patches[i].data, patches[i].size);
    printfsocket("patch %s: %d %d\n", patches[i].name, result, result < 0 ? errno : 0);
  }

  close(fd);
  return (result < 0 ? errno : 0);
}

int mount_procfs()
{
  int result = mkdir("/mnt/proc", 0777);
  if (result < 0 && (*__error()) != 17)
  {
    printfsocket("Failed to create /mnt/proc\n");
    return -1;
  }

  result = mount("procfs", "/mnt/proc", 0, NULL);
  if (result < 0)
  {
    printfsocket("Failed to mount procfs: %d\n", result, *__error());
    return -2;
  }

  return 0;
}

int do_patch()
{
  const patch_info shellcore_patches[] =
  {
    // call sceKernelIsGenuineCEX
    { NULL, 0x1486BB, "\x31\xC0\x90\x90\x90", 5 },
    { NULL, 0x6E523B, "\x31\xC0\x90\x90\x90", 5 },
    { NULL, 0x852C6B, "\x31\xC0\x90\x90\x90", 5 },
             
    // call nidf_libSceDipsw_0xD21CE9E2F639A83C
    { NULL, 0x1486E7, "\x31\xC0\x90\x90\x90", 5 },
    { NULL, 0x6E5267, "\x31\xC0\x90\x90\x90", 5 },
    { NULL, 0x852C97, "\x31\xC0\x90\x90\x90", 5 },

    // debug pkg free string
    { NULL, 0xD40F28, "free\0", 5 },

    // disable screenshot patch
    { NULL, 0xB4B0B, "\x90\x90\x90\x90\x90", 5 },

    { NULL, 0, NULL, 0 },
  };

  int result;

  int shell_pid = find_process("SceShellCore");
  if (shell_pid < 0)
  {
    printfsocket("Failed to find SceShellCore: %d\n", shell_pid);
    return -1;
  }
  printfsocket("Found SceShellCore at pid %d!\n", shell_pid);

  result = mount_procfs();
  if (result)
  {
    return -2;
  }

  printfsocket("Patching SceShellCore...\n");
  result = apply_patches(shell_pid, 0xFEC000, shellcore_patches);

  return result;
}
