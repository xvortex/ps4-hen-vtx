#include <stddef.h>
#include <stdint.h>

#include "sections.h"
#include "sparse.h"
#include "freebsd_helper.h"
#include "elf_helper.h"
#include "self_helper.h"
#include "sbl_helper.h"
#include "pfs_helper.h"
#include "rif_helper.h"
#include "ccp_helper.h"

void* (*real_malloc)(unsigned long size, void* type, int flags) PAYLOAD_BSS;
void (*real_free)(void* addr, void* type) PAYLOAD_BSS;
void* (*real_memcpy)(void* dst, const void* src, size_t len) PAYLOAD_BSS;
void* (*real_memset)(void *s, int c, size_t n) PAYLOAD_BSS;
int (*real_sx_xlock)(struct sx *sx, int opts) PAYLOAD_BSS;
int (*real_sx_xunlock)(struct sx *sx) PAYLOAD_BSS;
int (*real_fpu_kern_enter)(struct thread *td, struct fpu_kern_ctx *ctx, uint32_t flags) PAYLOAD_BSS;
int (*real_fpu_kern_leave)(struct thread *td, struct fpu_kern_ctx *ctx) PAYLOAD_BSS;

void* M_TEMP PAYLOAD_BSS;
void* fpu_ctx PAYLOAD_BSS;
uint8_t* mini_syscore_self_binary PAYLOAD_BSS;
struct sbl_map_list_entry** sbl_driver_mapped_pages PAYLOAD_BSS;
struct sx* sbl_pfs_sx PAYLOAD_BSS;

// Fself
void (*real_sceSblAuthMgrSmStart)(void**) PAYLOAD_BSS;
int (*real_sceSblServiceMailbox)(unsigned long service_id, uint8_t request[SBL_MSG_SERVICE_MAILBOX_MAX_SIZE], void* response) PAYLOAD_BSS;
int (*real_sceSblAuthMgrGetSelfInfo)(struct self_context* ctx, struct self_ex_info** info) PAYLOAD_BSS;
int (*real_sceSblAuthMgrIsLoadable2)(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info) PAYLOAD_BSS;
int (*real_sceSblAuthMgrVerifyHeader)(struct self_context* ctx) PAYLOAD_BSS;

extern int my_sceSblAuthMgrIsLoadable2(struct self_context* ctx, struct self_auth_info* old_auth_info, int path_id, struct self_auth_info* new_auth_info) PAYLOAD_CODE;
extern int my_sceSblAuthMgrVerifyHeader(struct self_context* ctx) PAYLOAD_CODE;
extern int my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response) PAYLOAD_CODE;
extern int my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox(unsigned long service_id, uint8_t* request, void* response) PAYLOAD_CODE;

// Fpkg
int (*real_sceSblPfsKeymgrGenKeys)(union pfs_key_blob* key_blob) PAYLOAD_BSS;
int (*real_sceSblPfsSetKeys)(uint32_t* ekh, uint32_t* skh, uint8_t* eekpfs, struct ekc* eekc, unsigned int pubkey_ver, unsigned int key_ver, struct pfs_header* hdr, size_t hdr_size, unsigned int type, unsigned int finalized, unsigned int is_disc) PAYLOAD_BSS;
int (*real_sceSblKeymgrClearKey)(uint32_t kh) PAYLOAD_BSS;
int (*real_sceSblKeymgrSetKeyForPfs)(union sbl_key_desc* key, unsigned int* handle) PAYLOAD_BSS;
int (*real_sceSblKeymgrSmCallfunc)(union keymgr_payload* payload) PAYLOAD_BSS;
int (*real_sceSblDriverSendMsg)(struct sbl_msg* msg, size_t size) PAYLOAD_BSS;
int (*real_RsaesPkcs1v15Dec2048CRT)(struct rsa_buffer* out, struct rsa_buffer* in, struct rsa_key* key) PAYLOAD_BSS;
int (*real_AesCbcCfb128Encrypt)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv) PAYLOAD_BSS;
int (*real_AesCbcCfb128Decrypt)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv) PAYLOAD_BSS;
void (*real_Sha256Hmac)(uint8_t hash[0x20], const uint8_t* data, size_t data_size, const uint8_t* key, int key_size) PAYLOAD_BSS;

extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif(union keymgr_payload* payload) PAYLOAD_CODE;
extern int my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new(union keymgr_payload* payload) PAYLOAD_CODE;
extern int my_sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg(struct sbl_msg* msg, size_t size) PAYLOAD_CODE;
extern int my_mountpfs__sceSblPfsSetKeys(uint32_t* ekh, uint32_t* skh, uint8_t* eekpfs, struct ekc* eekc, unsigned int pubkey_ver, unsigned int key_ver, struct pfs_header* hdr, size_t hdr_size, unsigned int type, unsigned int finalized, unsigned int is_disc) PAYLOAD_CODE;

struct real_info
{
  const size_t kernel_offset;
  const void* payload_target;
};

struct disp_info
{
  const size_t call_offset;
  const void* payload_target;
};

struct real_info real_infos[] PAYLOAD_DATA =
{
  { 0x10E140, &real_malloc },
  { 0x10E350, &real_free },
  { 0x1EA420, &real_memcpy },
  { 0x3201F0, &real_memset },
  { 0x0F5D00, &real_sx_xlock },
  { 0x0F5EC0, &real_sx_xunlock },
  { 0x1BFE80, &real_fpu_kern_enter },
  { 0x1BFF80, &real_fpu_kern_leave },

  { 0x14B4110, &M_TEMP },
  { 0x274C040, &fpu_ctx },
  { 0x14C9D48, &mini_syscore_self_binary },
  { 0x271E208, &sbl_driver_mapped_pages },
  { 0x271E5D8, &sbl_pfs_sx },

  // Fself
  { 0x641500, &real_sceSblAuthMgrSmStart },
  { 0x632160, &real_sceSblServiceMailbox },
  { 0x63c960, &real_sceSblAuthMgrGetSelfInfo },
  { 0x63C110, &real_sceSblAuthMgrIsLoadable2 },
  { 0x642760, &real_sceSblAuthMgrVerifyHeader },

  // Fpkg
  { 0x62D0A0, &real_sceSblPfsKeymgrGenKeys },
  { 0x61EBC0, &real_sceSblPfsSetKeys },
  { 0x62D730, &real_sceSblKeymgrClearKey },
  { 0x62D3A0, &real_sceSblKeymgrSetKeyForPfs },
  { 0x62DEC0, &real_sceSblKeymgrSmCallfunc },
  { 0x61D410, &real_sceSblDriverSendMsg },
  { 0x1FD6C0, &real_RsaesPkcs1v15Dec2048CRT },
  { 0x3A2800, &real_AesCbcCfb128Encrypt },
  { 0x3A2A30, &real_AesCbcCfb128Decrypt },
  { 0x2D52E0, &real_Sha256Hmac },

  { 0, NULL },
};

struct disp_info disp_infos[] PAYLOAD_DATA =
{
  // Fself
  { 0x63DFC1, &my_sceSblAuthMgrIsLoadable2 },
  { 0x63E71C, &my_sceSblAuthMgrVerifyHeader },
  { 0x63F338, &my_sceSblAuthMgrVerifyHeader },
  { 0x642DAB, &my_sceSblAuthMgrSmLoadSelfSegment__sceSblServiceMailbox },
  { 0x6439C2, &my_sceSblAuthMgrSmLoadSelfBlock__sceSblServiceMailbox },

  // Fpkg
  { 0x64C340, &my_sceSblKeymgrSmCallfunc_npdrm_decrypt_isolated_rif },
  { 0x64D11F, &my_sceSblKeymgrSmCallfunc_npdrm_decrypt_rif_new },
  { 0x623C85, &my_sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg },
  { 0x6AA6F5, &my_mountpfs__sceSblPfsSetKeys },
  { 0x6AA924, &my_mountpfs__sceSblPfsSetKeys },

  { 0, 0 },
};

// initialization, etc

PAYLOAD_CODE void my_entrypoint()
{
}

struct
{
  uint64_t signature;
  struct real_info* real_infos;
  struct disp_info* disp_infos;
  void* entrypoint;
}
payload_header PAYLOAD_HEADER =
{
  0x5041594C4F414430ull,
  real_infos,
  disp_infos,
  &my_entrypoint,
};

int _start()
{
  return 0;
}
