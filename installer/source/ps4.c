#include <ps4.h>

int* (*__error)();

int (*sceKernelLoadStartModule)(const char *name, size_t argc, const void *argv, unsigned int flags, int, int);

void *(*memset)(void *destination, int value, size_t num);
void *(*memcpy)(void *destination, const void *source, size_t num);
int (*sprintf)(char *str, const char *format, ...);

int (*sceSysUtilSendSystemNotificationWithText)(int messageType, char* message);

SYSCALL(unlink, 10);
SYSCALL(kexec, 11);
SYSCALL(mkdir, 136);
SYSCALL(getFunctionAddressByName, 591);

int loadModule(const char *name, int *idDestination)
{
	return syscall(594, name, 0, idDestination, 0);
}

void initKernel(void)
{
	int libKernelHandle;

	__error = NULL;

	if (loadModule("libkernel.sprx", &libKernelHandle))
		if (loadModule("libkernel_web.sprx", &libKernelHandle))
			loadModule("libkernel_sys.sprx", &libKernelHandle);

	RESOLVE(libKernelHandle, __error);
	RESOLVE(libKernelHandle, sceKernelLoadStartModule);
}
  
void initLibc(void)
{
	int libcHandle = sceKernelLoadStartModule("libSceLibcInternal.sprx", 0, NULL, 0, 0, 0);

	RESOLVE(libcHandle, memset);
	RESOLVE(libcHandle, memcpy);
	RESOLVE(libcHandle, sprintf);
}

void initSysUtil(void)
{
	int sysUtilHandle = sceKernelLoadStartModule("/system/common/lib/libSceSysUtil.sprx", 0, NULL, 0, 0, 0);
	RESOLVE(sysUtilHandle, sceSysUtilSendSystemNotificationWithText);
}
