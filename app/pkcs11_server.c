/*
 * run the module under test in another process. This code marshals arguements
 * back and forth
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dlfcn.h>


#include "pkcs11_lcl.h"
#ifdef ENABLE_NSS_DRBG
#include "loader.h"
#else
#define FREEBLVector void 
#endif
#include "pkcs11_server.h"

/* Command codes to select the function between the client and the server */
#define LIBRARY_CLOSE		0x00
#define SC_INITIALIZE		0x01
#define SC_FINIALIZE		0x02
#define SC_GET_INFO		0x03
#define SC_GET_FUNCTION_LIST	0x04
#define SC_GET_SLOT_LIST	0x05
#define SC_GET_SLOT_INFO	0x06
#define SC_GET_TOKEN_INFO	0x07
#define SC_GET_MECHANISM_LIST   0x08
#define SC_GET_MECHANISM_INFO	0x09
#define SC_INIT_TOKEN		0x0a
#define SC_INIT_PIN		0x0b
#define SC_INIT_SET_PIN		0x0c
#define SC_OPEN_SESSION		0x0d
#define SC_CLOSE_SESSION	0x0e
#define SC_CLOSE_ALL_SESSIONS	0x0f
#define SC_GET_SESSION_INFO	0x10
#define SC_GET_OPERATION_STATE	0x11
#define SC_SET_OPERATION_STATE	0x12
#define SC_LOGIN		0x13
#define SC_LOGOUT		0x14
#define SC_CREATE_OBJECT	0x15
#define SC_COPY_OBJECT		0x16
#define SC_DESTROY_OBJECT	0x17
#define SC_GET_OBJECT_SIZE	0x18
#define SC_GET_ATTRIBUTE	0x19
#define SC_SET_ATTRIBUTE	0x1a
#define SC_FIND_OBJECTS_INIT	0x1b
#define SC_FIND_OBJECTS		0x1c
#define SC_FIND_OBJECTS_FINAL	0x1d
#define SC_ENCRYPT_INIT		0x1e
#define SC_ENCRYPT		0x1f
#define SC_ENCRYPT_UPDATE	0x20
#define SC_ENCRYPT_FINAL	0x21
#define SC_DECRYPT_INIT		0x22
#define SC_DECRYPT		0x23
#define SC_DECRYPT_UPDATE	0x24
#define SC_DECRYPT_FINAL	0x25
#define SC_DIGEST_INIT		0x26
#define SC_DIGEST		0x27
#define SC_DIGEST_UPDATE	0x28
#define SC_DIGEST_KEY		0x29
#define SC_DIGEST_FINAL		0x2a
#define SC_SIGN_INIT		0x2b
#define SC_SIGN			0x2c
#define SC_SIGN_UPDATE		0x2d
#define SC_SIGN_FINAL		0x2e
#define SC_SIGN_RECOVER_INIT	0x2f
#define SC_SIGN_RECOVER		0x30
#define SC_VERIFY_INIT		0x31
#define SC_VERIFY		0x32
#define SC_VERIFY_UPDATE	0x33
#define SC_VERIFY_FINAL		0x34
#define SC_VERIFY_RECOVER_INIT	0x35
#define SC_VERIFY_RECOVER	0x36
#define SC_DIGEST_ENCRYPT_UPDATE 0x37
#define SC_DECRYPT_DIGEST_UPDATE 0x38
#define SC_SIGN_ENCRYPT_UPDATE	0x39
#define SC_DECRYPT_VERIFY_UPDATE 0x3a
#define SC_GENERATE_KEY		0x3b
#define SC_GENERATE_KEY_PAIR	0x3c
#define SC_WRAP_KEY		0x3d
#define SC_UNWRAP_KEY		0x3e
#define SC_DERIVE_KEY		0x3f
#define SC_SEED_RANDOM		0x40
#define SC_GENERATE_RANDOM	0x41
#define SC_GET_FUNCTION_STATUS	0x42
#define SC_CANCEL_FUNCTION	0x43
#define SC_WAIT_FOR_SLOT_EVENT	0x44
#define FREEBL_DRBG_INSTANIATE  0x80
#define FREEBL_DRBG_RESEED      0x81
#define FREEBL_DRBG_GENERATE    0x82
#define FREEBL_DRBG_UNINSTANTIATE 0x83

/*************************************************************************
 *                          marshalling helpers                          *
 *   Client and server are on the same machine, so we only need to       *
 *   marshal pointers.                                                   *
 *************************************************************************/
#define READVAR(fd,v) read(fd,&v,sizeof(v))
#define WRITEVAR(fd,v) write(fd,&v,sizeof(v))
#define READPTRVAR(fd,v) read(fd,v,sizeof(*v))
#define WRITEPTRVAR(fd,v) write(fd,v,sizeof(*v))

char *readstring(int fd)
{
   size_t len = 0;
   char *string;

   READVAR(fd,len);
   if (len == 0) {
	return NULL;
   }
   string = malloc(len+1);
   read(fd, string, len);
   string[len] = 0;
   return string;
}

void writestring(int fd, char *string)
{
   size_t len = string ? strlen(string) : 0;

   WRITEVAR(fd,len);
   if (len == 0) {
	return;
   }
   write(fd, string, len);
   return;
}

void *readbuf(int fd, size_t *plen)
{
   size_t len = 0;
   unsigned char *buf;

   READVAR(fd,len);
   if (len == 0) {
	*plen = 0;
	return NULL;
   }
   buf = malloc(len);
   read(fd, buf, len);
   *plen = len;
   return buf;
}

void writebuf(int fd, const void *in, size_t len)
{
   const unsigned char *buf = in;
   WRITEVAR(fd,len);
   if (len == 0) {
	return ;
   }
   write(fd, buf, len);
   return;
}

CK_ATTRIBUTE *readtemplate(int fd, CK_ULONG *pcount)
{
    CK_ULONG count;
    CK_ATTRIBUTE *template;
    int i;

    READVAR(fd, count);
    template = malloc(count * sizeof(*template));
    for (i=0; i < count; i++) {
	size_t len;
	READVAR(fd,template[i].type);
	template[i].pValue = readbuf(fd,&len);
	template[i].ulValueLen = len;
    }
    *pcount = count;
    return template;
}

void
freetemplate(CK_ATTRIBUTE *template, CK_ULONG count)
{
    int i;
    for (i=0; i < count; i++) {
	free(template[i].pValue);
    }
    free(template);
}

void
writetemplate(int fd, CK_ATTRIBUTE *template, CK_ULONG count)
{
    int i;
    WRITEVAR(fd, count);
    for (i=0; i < count; i++) {
	WRITEVAR(fd, template[i].type);
	writebuf(fd,template[i].pValue,template[i].ulValueLen);
    }
    return;
}

void readmechanism(int fd, CK_MECHANISM *mech)
{
    size_t len;
    CK_GCM_PARAMS *gcm_params;
    CK_CCM_PARAMS *ccm_params;
    READVAR(fd,mech->mechanism);
    switch (mech->mechanism) {
    case CKM_AES_GCM:
	gcm_params = readbuf(fd, &len);
	mech->pParameter = gcm_params;
	mech->ulParameterLen = len;
	gcm_params->pIv = readbuf(fd, &len);
	gcm_params->ulIvLen = len;
	gcm_params->pAAD = readbuf(fd, &len);
	gcm_params->ulAADLen = len;
	break;
    case CKM_AES_CCM:
	ccm_params = readbuf(fd, &len);
	mech->pParameter = ccm_params;
	mech->ulParameterLen = len;
	ccm_params->pNonce = readbuf(fd, &len);
	ccm_params->ulNonceLen = len;
	ccm_params->pAAD = readbuf(fd, &len);
	ccm_params->ulAADLen = len;
	break;
    default:
	mech->pParameter = readbuf(fd,&len);
	mech->ulParameterLen = len;
	break;
    }

}

void freemechanism(CK_MECHANISM *mech)
{
    CK_GCM_PARAMS *gcm_params;
    CK_CCM_PARAMS *ccm_params;
    switch (mech->mechanism) {
    case CKM_AES_GCM:
	gcm_params = (CK_GCM_PARAMS *)mech->pParameter;
	free(gcm_params->pIv);
	free(gcm_params->pAAD);
	free(gcm_params);
	break;
    case CKM_AES_CCM:
	ccm_params = (CK_CCM_PARAMS *)mech->pParameter;
	free(ccm_params->pNonce);
	free(ccm_params->pAAD);
	free(ccm_params);
	break;
    default:
	free(mech->pParameter);
	break;
    }
}

void writemechanism(int fd, CK_MECHANISM *mech)
{
    CK_GCM_PARAMS *gcm_params;
    CK_CCM_PARAMS *ccm_params;
    WRITEVAR(fd,mech->mechanism);
    switch (mech->mechanism) {
    case CKM_AES_GCM:
	gcm_params = (CK_GCM_PARAMS *)mech->pParameter;
	writebuf(fd,mech->pParameter,mech->ulParameterLen);
	writebuf(fd,gcm_params->pIv, gcm_params->ulIvLen);
	writebuf(fd,gcm_params->pAAD, gcm_params->ulAADLen);
	break;
    case CKM_AES_CCM:
	ccm_params = (CK_CCM_PARAMS *)mech->pParameter;
	writebuf(fd,mech->pParameter,mech->ulParameterLen);
	writebuf(fd,ccm_params->pNonce, ccm_params->ulNonceLen);
	writebuf(fd,ccm_params->pAAD, ccm_params->ulAADLen);
	break;
    default:
	writebuf(fd,mech->pParameter,mech->ulParameterLen);
	break;
    }

}
	
/*************************************************************************
 *                              The client                               *
 *************************************************************************/
#define __PASTE(x, y) x##y

/* ------------- forward declare all the client functions ------------- */
#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO

#define CK_PKCS11_FUNCTION_INFO(name) CK_RV __PASTE(CC, name)
#define CK_NEED_ARG_LIST 1

#include "pkcs11f.h"

/* ------------- build the CK_CRYPTO_TABLE ------------------------- */
static CK_FUNCTION_LIST client_template_table = {
    { 1, 10 },

#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO

#define CK_PKCS11_FUNCTION_INFO(name) \
    __PASTE(CC, name)                  \
    ,

#include "pkcs11f.h"

};

#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO

/******************** client Helper functions **********************/
/* get the client side function list */
CK_FUNCTION_LIST * pkcs11_client_get_function_list(void)
{
    /* probably should get the version number from the server here */
    /* unsigned char command = SC_GET_FUNCTION_LIST; */
    return &client_template_table;
}

/* squirrel away the pipe file descriptors */
static int request = -1;
static int reply = -1;
void pkcs11_client_set_fd(int request_fd, int reply_fd)
{
    request = request_fd;
    reply = reply_fd;
}

/* close down the server */
int pkcs11_client_close(int pid)
{
    int status;
    unsigned char command = LIBRARY_CLOSE;
    WRITEVAR(request, command);
    waitpid(pid, &status, 0);
    return status;
}

/******************** client freebl marshalling functions ********************/
#ifdef ENABLE_NSS_DRBG
SECStatus freebl_drbg_instantiate(const PRUint8 *entropy,
                                   unsigned int entropy_len,
                                   const PRUint8 *nonce,
                                   unsigned int nonce_len,
                                   const PRUint8 *personal_string,
                                   unsigned int ps_len)
{
    unsigned char command = FREEBL_DRBG_INSTANIATE;
    SECStatus rv;
    WRITEVAR(request, command);
    writebuf(request, entropy, entropy_len);
    writebuf(request, nonce, nonce_len);
    writebuf(request, personal_string, ps_len);
    READVAR(reply, rv);
    return rv;
}

SECStatus freebl_drbg_reseed(const PRUint8 *entropy,
                               unsigned int entropy_len,
                               const PRUint8 *additional,
                               unsigned int additional_len)
{
    unsigned char command = FREEBL_DRBG_RESEED;
    SECStatus rv;
    WRITEVAR(request, command);
    writebuf(request, entropy, entropy_len);
    writebuf(request, additional, additional_len);
    READVAR(reply, rv);
    return rv;
}

SECStatus freebl_drbg_generate(PRUint8 *bytes,
                                 unsigned int bytes_len,
                                 const PRUint8 *additional,
                                 unsigned int additional_len)
{
    unsigned char command = FREEBL_DRBG_GENERATE;
    SECStatus rv;
    WRITEVAR(request, command);
    WRITEVAR(request, bytes_len);
    writebuf(request, additional, additional_len);
    READVAR(reply, rv);
    if (rv != SECSuccess) {
	return rv;
    }
    read(reply, bytes, bytes_len);
    return rv;
}

SECStatus freebl_drbg_uninstantiate()
{
    unsigned char command = FREEBL_DRBG_UNINSTANTIATE;
    SECStatus rv;
    WRITEVAR(request, command);
    READVAR(reply, rv);
    return rv;
}
#endif

/******************** client pkcs11 marshalling functions ********************/
CK_RV CCC_Initialize(CK_VOID_PTR pInitArgs)
{
    unsigned char command = SC_INITIALIZE;
    CK_RV crv;
    CK_C_INITIALIZE_ARGS *initargs = (CK_C_INITIALIZE_ARGS *)pInitArgs;

    WRITEVAR(request, command);
    WRITEPTRVAR(request, initargs);
    /* In theory we should also deal with the MUTEXES, but 
     * we know we aren't using mutexes in the avcp code */
    if (initargs->LibraryParameters != NULL) {
	writestring(request, (char *)initargs->LibraryParameters);
    }
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_Finalize(CK_VOID_PTR pReserved)
{
    unsigned char command = SC_FINIALIZE;
    CK_RV crv;
    WRITEVAR(request, command);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_GetInfo(CK_INFO_PTR pInfo)
{
    unsigned char command =SC_GET_INFO;
    CK_RV crv;
    WRITEVAR(request, command);
    READVAR(reply, crv);
    if (crv == CKR_OK) {
	READPTRVAR(reply,pInfo);
    }
    return crv;
}
CK_RV CCC_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    /* don't actually call the sever, just user our helper function */
    *ppFunctionList = pkcs11_client_get_function_list();
    return CKR_OK;
}

CK_RV CCC_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
		CK_ULONG_PTR pulCount)
{
    unsigned char command = SC_GET_SLOT_LIST;
    CK_RV crv;
    size_t slotListLen;
    CK_SLOT_ID *slotList;
    WRITEVAR(request, command);
    WRITEVAR(request, tokenPresent);
    WRITEVAR(request, pSlotList);
    WRITEPTRVAR(request, pulCount);
    READVAR(reply, crv);
    /* always return the count, even on errors */
    READPTRVAR(reply, pulCount);
    if (pSlotList && crv == CKR_OK) {
        slotList = readbuf(reply, &slotListLen);
	memcpy(pSlotList,slotList, slotListLen);
	free(slotList);
    }
    return crv;
}

CK_RV CCC_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    unsigned char command = SC_GET_SLOT_INFO;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, slotID);
    READVAR(reply, crv);
    if (crv == CKR_OK) {
        READPTRVAR(reply, pInfo);
    }
    return crv;
}

CK_RV CCC_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    unsigned char command = SC_GET_TOKEN_INFO;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, slotID);
    READVAR(reply, crv);
    if (crv == CKR_OK) {
        READPTRVAR(reply, pInfo);
    }
    return crv;
}

CK_RV CCC_GetMechanismList(CK_SLOT_ID slotID,
    	   CK_MECHANISM_TYPE_PTR pMechanismList,
    	   CK_ULONG_PTR pulCount)
{
    unsigned char command = SC_GET_MECHANISM_LIST;
    CK_RV crv;
    size_t mechListLen;
    CK_MECHANISM_TYPE *mechList;
    WRITEVAR(request, command);
    WRITEVAR(request, slotID);
    WRITEVAR(request, pMechanismList);
    WRITEPTRVAR(request, pulCount);
    READVAR(reply, crv);
    /* always return the count, even on errors */
    READPTRVAR(reply, pulCount);
    if (pMechanismList && crv == CKR_OK) {
        mechList = readbuf(reply, &mechListLen);
	memcpy(pMechanismList, mechList, mechListLen);
	free(mechList);
    }
    return crv;
}

CK_RV CCC_GetMechanismInfo( CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo)
{
    unsigned char command = SC_GET_MECHANISM_INFO;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, slotID);
    WRITEVAR(request, type);
    READVAR(reply, crv);
    if (crv == CKR_OK) {
        READPTRVAR(reply, pInfo);
    }
    return crv;
}

CK_RV CCC_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    /* unsigned char command = SC_INIT_TOKEN: */
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen)
{
	/*case SC_INIT_PIN: */
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_SetPIN( CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
    CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
/*	case SC_INIT_SET_PIN: */
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
    CK_VOID_PTR pApplication, CK_NOTIFY Notify,
    CK_SESSION_HANDLE_PTR phSession)
{
    unsigned char command = SC_OPEN_SESSION;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, slotID);
    WRITEVAR(request, flags);
    READVAR(reply, crv);
    if (crv == CKR_OK) {
        READPTRVAR(reply, phSession);
    }
    return crv;
}

CK_RV CCC_CloseSession(CK_SESSION_HANDLE hSession)
{
    unsigned char command = SC_CLOSE_SESSION;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    READVAR(reply, crv);
    return crv;
}
CK_RV CCC_CloseAllSessions(CK_SLOT_ID slotID)
{
    unsigned char command = SC_CLOSE_ALL_SESSIONS;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, slotID);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    unsigned char command = SC_GET_SESSION_INFO;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    READVAR(reply, crv);
    if (crv == CKR_OK) {
        READPTRVAR(reply, pInfo);
    }
    return crv;
}

CK_RV CCC_GetOperationState(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
/*	case SC_GET_OPERATION_STATE:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_SetOperationState(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen,
    CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
/*	case SC_SET_OPERATION_STATE:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_Login( CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
    CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
/*	case SC_LOGIN:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_Logout(CK_SESSION_HANDLE hSession)
{
/*	case SC_LOGOUT:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_CreateObject(CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phObject)
{
    unsigned char command = SC_CREATE_OBJECT;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writetemplate(request, pTemplate, ulCount);
    READVAR(reply, crv);
    if (crv == CKR_OK) {
        READPTRVAR(reply, phObject);
    }
    return crv;
}

CK_RV CCC_CopyObject(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
    unsigned char command = SC_COPY_OBJECT;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    WRITEVAR(request, hObject);
    writetemplate(request, pTemplate, ulCount);
    READVAR(reply, crv);
    if (crv == CKR_OK) {
        READPTRVAR(reply, phNewObject);
    }
    return crv;
}

CK_RV CCC_DestroyObject( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    unsigned char command = SC_DESTROY_OBJECT;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    WRITEVAR(request, hObject);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ULONG_PTR pulSize)
{
    unsigned char command = SC_GET_OBJECT_SIZE;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    WRITEVAR(request, hObject);
    READVAR(reply, crv);
    if (crv == CKR_OK) {
        READPTRVAR(reply, pulSize);
    }
    return crv;
}

CK_RV CCC_GetAttributeValue(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
/*	case SC_GET_ATTRIBUTE:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_SetAttributeValue(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
/*	case SC_SET_ATTRIBUTE:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_FindObjectsInit(CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
/*	case SC_FIND_OBJECTS_INIT:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_FindObjects(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
    CK_ULONG_PTR pulObjectCount)
{
/*	case SC_FIND_OBJECTS:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
/*	case SC_FIND_OBJECTS_FINAL:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_EncryptInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{
    unsigned char command = SC_ENCRYPT_INIT;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writemechanism(request, pMechanism);
    WRITEVAR(request, hKey);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_Encrypt( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    unsigned char command = SC_ENCRYPT;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pData, ulDataLen);
    WRITEPTRVAR(request,pulEncryptedDataLen);
    READVAR(reply, crv);
    READPTRVAR(reply, pulEncryptedDataLen);
    if (crv == CKR_OK) {
        read(reply, pEncryptedData, *pulEncryptedDataLen);
    }
    return crv;
}

CK_RV CCC_EncryptUpdate( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    unsigned char command = SC_ENCRYPT_UPDATE;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pPart, ulPartLen);
    WRITEPTRVAR(request, pulEncryptedPartLen);
    READVAR(reply, crv);
    READPTRVAR(reply, pulEncryptedPartLen);
    if (crv == CKR_OK) {
        read(reply, pEncryptedPart, *pulEncryptedPartLen);
    }
    return crv;
}

CK_RV CCC_EncryptFinal( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
    unsigned char command = SC_ENCRYPT_FINAL;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    WRITEPTRVAR(request, pulLastEncryptedPartLen);
    READVAR(reply, crv);
    READPTRVAR(reply, pulLastEncryptedPartLen);
    if (crv == CKR_OK) {
        read(reply, pLastEncryptedPart, *pulLastEncryptedPartLen);
    }
    return crv;
}

CK_RV CCC_DecryptInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{
    unsigned char command = SC_DECRYPT_INIT;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writemechanism(request, pMechanism);
    WRITEVAR(request, hKey);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_Decrypt( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
    CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    unsigned char command = SC_DECRYPT;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pEncryptedData, ulEncryptedDataLen);
    WRITEPTRVAR(request, pulDataLen);
    READVAR(reply, crv);
    READPTRVAR(reply, pulDataLen);
    if (crv == CKR_OK) {
        read(reply, pData, *pulDataLen);
    }
    return crv;
}

CK_RV CCC_DecryptUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    unsigned char command = SC_DECRYPT_UPDATE;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pEncryptedPart, ulEncryptedPartLen);
    WRITEPTRVAR(request, pulPartLen);
    READVAR(reply, crv);
    READPTRVAR(reply, pulPartLen);
    if (crv == CKR_OK) {
        read(reply, pPart, *pulPartLen);
    }
    return crv;
}

CK_RV CCC_DecryptFinal( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
    unsigned char command = SC_DECRYPT_FINAL;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    WRITEPTRVAR(request, pulLastPartLen);
    READVAR(reply, crv);
    READPTRVAR(reply, pulLastPartLen);
    if (crv == CKR_OK) {
        read(reply, pLastPart, *pulLastPartLen);
    }
    return crv;
}

CK_RV CCC_DigestInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    unsigned char command = SC_DIGEST_INIT;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writemechanism(request, pMechanism);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_Digest( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    unsigned char command = SC_DIGEST;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pData, ulDataLen);
    WRITEPTRVAR(request, pulDigestLen);
    READVAR(reply, crv);
    READPTRVAR(reply, pulDigestLen);
    if (crv == CKR_OK) {
        read(reply, pDigest, *pulDigestLen);
    }
    return crv;
}

CK_RV CCC_DigestUpdate( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    unsigned char command = SC_DIGEST_UPDATE;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pPart, ulPartLen);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    unsigned char command = SC_DIGEST_KEY;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    WRITEVAR(request, hKey);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_DigestFinal(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    unsigned char command = SC_DIGEST_FINAL;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    WRITEPTRVAR(request, pulDigestLen);
    READVAR(reply, crv);
    READPTRVAR(reply, pulDigestLen);
    if (crv == CKR_OK) {
        read(reply, pDigest, *pulDigestLen);
    }
    return crv;
}

CK_RV CCC_SignInit( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey)
{
    unsigned char command = SC_SIGN_INIT;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writemechanism(request, pMechanism);
    WRITEVAR(request, hKey);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_Sign(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    unsigned char command = SC_SIGN;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pData, ulDataLen);
    WRITEPTRVAR(request, pulSignatureLen);
    READVAR(reply, crv);
    READPTRVAR(reply, pulSignatureLen);
    if (crv == CKR_OK) {
        read(reply, pSignature, *pulSignatureLen);
    }
    return crv;
}

CK_RV CCC_SignUpdate( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    unsigned char command = SC_SIGN_UPDATE;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pPart, ulPartLen);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_SignFinal( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    unsigned char command = SC_SIGN_FINAL;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    WRITEPTRVAR(request, pulSignatureLen);
    READVAR(reply, crv);
    READPTRVAR(reply, pulSignatureLen);
    if (crv == CKR_OK) {
        read(reply, pSignature, *pulSignatureLen);
    }
    return crv;
}

CK_RV CCC_SignRecoverInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    unsigned char command = SC_SIGN_RECOVER_INIT;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writemechanism(request, pMechanism);
    WRITEVAR(request, hKey);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_SignRecover(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    unsigned char command = SC_SIGN_RECOVER;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pData, ulDataLen);
    WRITEPTRVAR(request, pulSignatureLen);
    READVAR(reply, crv);
    READPTRVAR(reply, pulSignatureLen);
    if (crv == CKR_OK) {
        read(reply, pSignature, *pulSignatureLen);
    }
    return crv;
}

CK_RV CCC_VerifyInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    unsigned char command = SC_VERIFY_INIT;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writemechanism(request, pMechanism);
    WRITEVAR(request, hKey);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_Verify(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData, CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    unsigned char command = SC_VERIFY;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pData, ulDataLen);
    writebuf(request, pSignature, ulSignatureLen);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_VerifyUpdate( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    unsigned char command = SC_VERIFY_UPDATE;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pPart, ulPartLen);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_VerifyFinal( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    unsigned char command = SC_VERIFY_FINAL;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pSignature, ulSignatureLen);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    unsigned char command = SC_VERIFY_RECOVER_INIT;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writemechanism(request, pMechanism);
    WRITEVAR(request, hKey);
    READVAR(reply, crv);
    return crv;
}

CK_RV CCC_VerifyRecover(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
    CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    unsigned char command = SC_SIGN_RECOVER;
    CK_RV crv;
    WRITEVAR(request, command);
    WRITEVAR(request, hSession);
    writebuf(request, pSignature, ulSignatureLen);
    WRITEPTRVAR(request, pulDataLen);
    READVAR(reply, crv);
    READPTRVAR(reply, pulDataLen);
    if (crv == CKR_OK) {
        read(reply, pData, *pulDataLen);
    }
    return crv;
}

	
CK_RV CCC_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
/*	case SC_DIGEST_ENCRYPT_UPDATE:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
/*	case SC_DECRYPT_DIGEST_UPDATE:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
/*	case SC_SIGN_ENCRYPT_UPDATE:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_DecryptVerifyUpdate( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
/*	case SC_DECRYPT_VERIFY_UPDATE:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_GenerateKey (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
/*	case SC_GENERATE_KEY:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_GenerateKeyPair(CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
/*	case SC_GENERATE_KEY_PAIR:	*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
    CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
/*	case SC_WRAP_KEY	*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_UnwrapKey( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
/*	case SC_UNWRAP_KEY:	*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
/*	case SC_DERIVE_KEY:	*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_SeedRandom( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
/*	case SC_SEED_RANDOM:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_GenerateRandom( CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
/*	case SC_GENERATE_RANDOM:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
/*	case SC_GET_FUNCTION_STATUS:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_CancelFunction(CK_SESSION_HANDLE hSession)
{
/*	case SC_CANCEL_FUNCTION:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV CCC_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
    CK_VOID_PTR pRserved)
{
/*	case SC_WAIT_FOR_SLOT_EVENT:*/
    return CKR_FUNCTION_NOT_SUPPORTED;
}
   
/*************************************************************************
 *                              The server                               *
 *************************************************************************/
void
pkcs11_server(int request_fd, int reply_fd, 
		const CK_FUNCTION_LIST *pkcs11_function_list, 
		const FREEBLVector *freebl_function_list,
		void *library_handle, void *freebl_library_handle)
{
    int exit=0;
    unsigned char command;
    int rv;
    CK_RV crv;
    int retry= 0;

    while (!exit) {
	rv = READVAR(request_fd, command);
	if (rv < 0) {
	    retry++;
	    if (retry == 10)
	    exit = 1;
	    perror("Read from pipe failed");
	    continue;
	}
	retry = 0;
	switch (command) {
	case LIBRARY_CLOSE:
	    dlclose(library_handle);
	    if (freebl_library_handle) {
		dlclose(freebl_library_handle);
	    }
	    /* should check the status dlclose and return it here */
	    exit = 0;
	    break;

#ifdef ENABLE_NSS_DRBG
	case FREEBL_DRBG_INSTANIATE:
	    {
		PRUint8 *entropy;
                size_t entropy_len;
                PRUint8 *nonce;
                size_t nonce_len;
                PRUint8 *personal_string;
                size_t  ps_len;
		SECStatus rv;

		entropy = readbuf(request, &entropy_len);
		nonce = readbuf(request, &nonce_len);
		personal_string = readbuf(request, &ps_len);
		if (freebl_function_list) {
		    rv = (*freebl_function_list->p_PRNGTEST_Instantiate)(
				entropy, entropy_len, nonce, 
				nonce_len, personal_string, ps_len);
		} else {
		    rv = SECFailure;
		}
		free(entropy);
		free(nonce);
		free(personal_string);
		WRITEVAR(reply, rv);
	    }
	    break;
	case FREEBL_DRBG_RESEED:
	    {
		PRUint8 *entropy;
                size_t entropy_len;
                PRUint8 *additional;
                size_t  additional_len;
		SECStatus rv;

		entropy = readbuf(request, &entropy_len);
		additional = readbuf(request, &additional_len);
		if (freebl_function_list) {
		    rv = (*freebl_function_list->p_PRNGTEST_Reseed)(
			entropy, entropy_len, additional, additional_len);
		} else {
		    rv = SECFailure;
		}
		free(entropy);
		free(additional);
		WRITEVAR(reply, rv);
	    }
	    break;
	case FREEBL_DRBG_GENERATE:
	    {
		PRUint8 *bytes;
                unsigned int bytes_len;
                PRUint8 *additional;
                size_t additional_len;
		SECStatus rv;

		READVAR(request, bytes_len);
		additional = readbuf(request, &additional_len);
		bytes = malloc(bytes_len);
		if (freebl_function_list) {
		    rv = (*freebl_function_list->p_PRNGTEST_Generate)(
			bytes, bytes_len, additional, additional_len);
		} else {
		    rv = SECFailure;
		}
		free(additional);
		WRITEVAR(reply, rv);
		if (rv == SECSuccess) {
		    write(reply, bytes, bytes_len);
		}
		free(bytes);
	    }
	    break;
	case FREEBL_DRBG_UNINSTANTIATE:
	    {
		SECStatus rv;

		if (freebl_function_list) {
		    rv = (*freebl_function_list->p_PRNGTEST_Uninstantiate)();
		} else {
		    rv = SECFailure;
		}
		WRITEVAR(reply, rv);
	    }
	    break;
#endif

	case SC_INITIALIZE:
	    {
		CK_C_INITIALIZE_ARGS initargs;
		READVAR(request_fd, initargs);
		/* In theory we should also deal with the MUTEXES, but 
		 * we know we aren't using mutexes in the avcp code */
		if (initargs.LibraryParameters != NULL) {
		    initargs.LibraryParameters = 
			(CK_CHAR_PTR *)readstring(request_fd);
		}
		crv = (*pkcs11_function_list->C_Initialize)(&initargs);
		free(initargs.LibraryParameters);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_FINIALIZE:
	    {
		crv = (*pkcs11_function_list->C_Finalize)(NULL);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_GET_INFO:
	    {
		CK_INFO info;
		crv = (*pkcs11_function_list->C_GetInfo)(&info);
		WRITEVAR(reply_fd, crv);
		if (crv == CKR_OK) {
		    WRITEVAR(reply_fd, info);
		}
	    }
	    break;
	case SC_GET_FUNCTION_LIST:
	    {
		crv = CKR_OK;
		WRITEVAR(reply_fd, crv);
		write(reply_fd,pkcs11_function_list, 
				sizeof(*pkcs11_function_list));
	    }
	    break;
	case SC_GET_SLOT_LIST:
	    {
		CK_BBOOL tokenPresent;
		CK_SLOT_ID *slotList;
		CK_ULONG       count;
		size_t	slotListLen;
		READVAR(request_fd, tokenPresent);
		READVAR(request_fd, slotList);
		READVAR(request_fd, count);
		if (slotList) {
		    slotListLen = count * sizeof(*slotList);
		    slotList = malloc(slotListLen);
		}
		crv = (*pkcs11_function_list->C_GetSlotList)(
			tokenPresent, slotList, &count);
		WRITEVAR(reply_fd, crv);
		/* always return the count, even on errors */
		WRITEVAR(reply_fd, count);
		if (slotList && crv == CKR_OK) {
		    writebuf(reply_fd, slotList, slotListLen);
		}
	    }
	    break;
	case SC_GET_SLOT_INFO:
	    {
		CK_SLOT_ID slot;
		CK_SLOT_INFO slotInfo;
		READVAR(request_fd, slot);
		crv = (*pkcs11_function_list->C_GetSlotInfo)(
			slot, &slotInfo);
		WRITEVAR(reply_fd, crv);
		if (crv == CKR_OK) {
		    WRITEVAR(reply_fd, slotInfo);
		}
	    }
	    break;
	case SC_GET_TOKEN_INFO:
	    {
		CK_SLOT_ID slot;
		CK_TOKEN_INFO tokenInfo;
		READVAR(request_fd, slot);
		crv = (*pkcs11_function_list->C_GetTokenInfo)(
			slot, &tokenInfo);
		WRITEVAR(reply_fd, crv);
		if (crv == CKR_OK) {
		    WRITEVAR(reply_fd, tokenInfo);
		}
	    }
	    break;
	case SC_GET_MECHANISM_LIST:
	    {
		CK_SLOT_ID slot;
		CK_MECHANISM_TYPE *mechList;
		CK_ULONG       count;
		size_t	mechListLen;
		READVAR(request_fd, slot);
		READVAR(request_fd, mechList);
		READVAR(request_fd, count);
		if (mechList) {
		    mechListLen = count * sizeof(*mechList);
		    mechList = malloc(mechListLen);
		}
		crv = (*pkcs11_function_list->C_GetMechanismList)(
			slot, mechList, &count);
		WRITEVAR(reply_fd, crv);
		/* always return the count, even on errors */
		WRITEVAR(reply_fd, count);
		if (mechList && crv == CKR_OK) {
		    writebuf(reply_fd, mechList, mechListLen);
		}
	    }
	    break;
	case SC_GET_MECHANISM_INFO:
	    {
		CK_SLOT_ID slot;
		CK_MECHANISM_TYPE mech;
		CK_MECHANISM_INFO mechInfo;
		READVAR(request_fd, slot);
		READVAR(request_fd, mech);
		crv = (*pkcs11_function_list->C_GetMechanismInfo)(
			slot, mech, &mechInfo);
		WRITEVAR(reply_fd, crv);
		if (crv == CKR_OK) {
		    WRITEVAR(reply_fd, mechInfo);
		}
	    }
	    break;
	/* skip the functions we don't actually need */
	case SC_INIT_TOKEN:
	case SC_INIT_PIN:
	case SC_INIT_SET_PIN:
	    crv = CKR_FUNCTION_NOT_SUPPORTED;
	    WRITEVAR(reply_fd, crv);
	    break;
	case SC_OPEN_SESSION:
	    {
		CK_SLOT_ID slot;
		CK_FLAGS flags;
		CK_SESSION_HANDLE session;
		READVAR(request_fd, slot);
		READVAR(request_fd, flags);
		crv = (*pkcs11_function_list->C_OpenSession)(
			slot, flags, NULL, NULL, &session);
		WRITEVAR(reply_fd, crv);
		if (crv == CKR_OK) {
		    WRITEVAR(reply_fd, session);
		}
	    }
	    break;
	case SC_CLOSE_SESSION:
	    {
		CK_SESSION_HANDLE session;
		READVAR(request_fd, session);
		crv = (*pkcs11_function_list->C_CloseSession)(session);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_CLOSE_ALL_SESSIONS:
	    {
		CK_SLOT_ID slot;
		READVAR(request_fd, slot);
		crv = (*pkcs11_function_list->C_CloseAllSessions)(slot);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_GET_SESSION_INFO:
	    {
		CK_SESSION_HANDLE session;
		CK_SESSION_INFO sessInfo;
		READVAR(request_fd, session);
		crv = (*pkcs11_function_list->C_GetSessionInfo)(
			session, &sessInfo);
		WRITEVAR(reply_fd, crv);
		if (crv == CKR_OK) {
		    WRITEVAR(reply_fd, sessInfo);
		}
	    }
	    break;
	/* skip the functions we don't actually need */
	case SC_GET_OPERATION_STATE:
	case SC_SET_OPERATION_STATE:
	case SC_LOGIN:
	case SC_LOGOUT:
	    crv = CKR_FUNCTION_NOT_SUPPORTED;
	    WRITEVAR(reply_fd, crv);
	    break;
	case SC_CREATE_OBJECT:
	    {
		CK_SESSION_HANDLE session;
		CK_ATTRIBUTE *template;
		CK_ULONG count;
		CK_OBJECT_HANDLE object;
		READVAR(request_fd, session);
		template = readtemplate(request_fd, &count);
		crv = (*pkcs11_function_list->C_CreateObject)(
			session, template, count, &object);
		freetemplate(template,count);
		WRITEVAR(reply_fd, crv);
		if (crv == CKR_OK) {
		    WRITEVAR(reply_fd, object);
		}
	    }
	    break;
	case SC_COPY_OBJECT:
	    {
		CK_SESSION_HANDLE session;
		CK_OBJECT_HANDLE sourceObject;
		CK_ATTRIBUTE *template;
		CK_ULONG count;
		CK_OBJECT_HANDLE object;
		READVAR(request_fd, session);
		READVAR(request_fd, sourceObject);
		template = readtemplate(request_fd, &count);
		crv = (*pkcs11_function_list->C_CopyObject)(
			session, sourceObject, template, count, &object);
		freetemplate(template,count);
		WRITEVAR(reply_fd, crv);
		if (crv == CKR_OK) {
		    WRITEVAR(reply_fd, object);
		}
	    }
	    break;
	case SC_DESTROY_OBJECT:
	    {
		CK_SESSION_HANDLE session;
		CK_OBJECT_HANDLE object;
		READVAR(request_fd, session);
		READVAR(request_fd, object);
		crv = (*pkcs11_function_list->C_DestroyObject)(
			session, object);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_GET_OBJECT_SIZE:
	    {
		CK_SESSION_HANDLE session;
		CK_OBJECT_HANDLE object;
		CK_ULONG size;
		READVAR(request_fd, session);
		READVAR(request_fd, object);
		crv = (*pkcs11_function_list->C_GetObjectSize)(
			session, object, &size);
		WRITEVAR(reply_fd, crv);
		if (crv == CKR_OK) {
		    WRITEVAR(reply_fd, size);
		}
	    }
	    break;
	/* skip the functions we don't actually need */
	case SC_GET_ATTRIBUTE:
	case SC_SET_ATTRIBUTE:
	case SC_FIND_OBJECTS_INIT:
	case SC_FIND_OBJECTS:
	case SC_FIND_OBJECTS_FINAL:
	    crv = CKR_FUNCTION_NOT_SUPPORTED;
	    WRITEVAR(reply_fd, crv);
	    break;
	case SC_ENCRYPT_INIT:
	    {
		CK_SESSION_HANDLE session;
		CK_MECHANISM mech;
		CK_OBJECT_HANDLE key;
		READVAR(request_fd, session);
		readmechanism(request_fd, &mech);
		READVAR(request_fd, key);
		crv = (*pkcs11_function_list->C_EncryptInit)(
			session, &mech, key);
		freemechanism(&mech);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_ENCRYPT:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *inData;
		CK_ULONG inDataLen;
		CK_BYTE *outData = NULL;
		CK_ULONG outDataLen;
		size_t len;
		READVAR(request_fd, session);
		inData=readbuf(request_fd,&len);
		inDataLen = len;
		READVAR(request_fd,outDataLen);
		if (outDataLen) {
		    outData = malloc(outDataLen);
		}
		crv = (*pkcs11_function_list->C_Encrypt)(
			session, inData, inDataLen, outData, &outDataLen);
		WRITEVAR(reply_fd, crv);
		WRITEVAR(reply_fd, outDataLen);
		if (crv == CKR_OK) {
		    write(reply_fd, outData, outDataLen);
		}
	    }
	    break;
	case SC_ENCRYPT_UPDATE:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *inData;
		CK_ULONG inDataLen;
		CK_BYTE *outData = NULL;
		CK_ULONG outDataLen;
		size_t len;
		READVAR(request_fd, session);
		inData=readbuf(request_fd,&len);
		inDataLen = len;
		READVAR(request_fd,outDataLen);
		if (outDataLen) {
		    outData = malloc(outDataLen);
		}
		crv = (*pkcs11_function_list->C_EncryptUpdate)(
			session, inData, inDataLen, outData, &outDataLen);
		WRITEVAR(reply_fd, crv);
		WRITEVAR(reply_fd, outDataLen);
		if (crv == CKR_OK) {
		    write(reply_fd, outData, outDataLen);
		}
	    }
	    break;
	case SC_ENCRYPT_FINAL:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *outData = NULL;
		CK_ULONG outDataLen;
		READVAR(request_fd, session);
		READVAR(request_fd,outDataLen);
		if (outDataLen) {
		    outData = malloc(outDataLen);
		}
		crv = (*pkcs11_function_list->C_EncryptFinal)(
			session, outData, &outDataLen);
		WRITEVAR(reply_fd, crv);
		WRITEVAR(reply_fd, outDataLen);
		if (crv == CKR_OK) {
		    write(reply_fd, outData, outDataLen);
		}
	    }
	    break;
	case SC_DECRYPT_INIT:
	    {
		CK_SESSION_HANDLE session;
		CK_MECHANISM mech;
		CK_OBJECT_HANDLE key;
		READVAR(request_fd, session);
		readmechanism(request_fd, &mech);
		READVAR(request_fd, key);
		crv = (*pkcs11_function_list->C_DecryptInit)(
			session, &mech, key);
		freemechanism(&mech);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_DECRYPT:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *inData;
		CK_ULONG inDataLen;
		CK_BYTE *outData = NULL;
		CK_ULONG outDataLen;
		size_t len;
		READVAR(request_fd, session);
		inData=readbuf(request_fd,&len);
		inDataLen = len;
		READVAR(request_fd,outDataLen);
		if (outDataLen) {
		    outData = malloc(outDataLen);
		}
		crv = (*pkcs11_function_list->C_Decrypt)(
			session, inData, inDataLen, outData, &outDataLen);
		WRITEVAR(reply_fd, crv);
		WRITEVAR(reply_fd, outDataLen);
		if (crv == CKR_OK) {
		    write(reply_fd, outData, outDataLen);
		}
	    }
	    break;
	case SC_DECRYPT_UPDATE:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *inData;
		CK_ULONG inDataLen;
		CK_BYTE *outData = NULL;
		CK_ULONG outDataLen;
		size_t len;
		READVAR(request_fd, session);
		inData=readbuf(request_fd,&len);
		inDataLen = len;
		READVAR(request_fd,outDataLen);
		if (outDataLen) {
		    outData = malloc(outDataLen);
		}
		crv = (*pkcs11_function_list->C_DecryptUpdate)(
			session, inData, inDataLen, outData, &outDataLen);
		WRITEVAR(reply_fd, crv);
		WRITEVAR(reply_fd, outDataLen);
		if (crv == CKR_OK) {
		    write(reply_fd, outData, outDataLen);
		}
	    }
	    break;
	case SC_DECRYPT_FINAL:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *outData = NULL;
		CK_ULONG outDataLen;
		READVAR(request_fd, session);
		READVAR(request_fd,outDataLen);
		if (outDataLen) {
		    outData = malloc(outDataLen);
		}
		crv = (*pkcs11_function_list->C_DecryptFinal)(
			session, outData, &outDataLen);
		WRITEVAR(reply_fd, crv);
		WRITEVAR(reply_fd, outDataLen);
		if (crv == CKR_OK) {
		    write(reply_fd, outData, outDataLen);
		}
	    }
	    break;
	case SC_DIGEST_INIT:
	    {
		CK_SESSION_HANDLE session;
		CK_MECHANISM mech;
		READVAR(request_fd, session);
		readmechanism(request_fd, &mech);
		crv = (*pkcs11_function_list->C_DigestInit)(
			session, &mech);
		freemechanism(&mech);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_DIGEST:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *inData;
		CK_ULONG inDataLen;
		CK_BYTE *outData = NULL;
		CK_ULONG outDataLen;
		size_t len;
		READVAR(request_fd, session);
		inData=readbuf(request_fd,&len);
		inDataLen = len;
		READVAR(request_fd,outDataLen);
		if (outDataLen) {
		    outData = malloc(outDataLen);
		}
		crv = (*pkcs11_function_list->C_Digest)(
			session, inData, inDataLen, outData, &outDataLen);
		WRITEVAR(reply_fd, crv);
		WRITEVAR(reply_fd, outDataLen);
		if (crv == CKR_OK) {
		    write(reply_fd, outData, outDataLen);
		}
	    }
	    break;
	case SC_DIGEST_UPDATE:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *inData;
		CK_ULONG inDataLen;
		size_t len;
		READVAR(request_fd, session);
		inData=readbuf(request_fd,&len);
		inDataLen = len;
		crv = (*pkcs11_function_list->C_DigestUpdate)( session, 
					inData, inDataLen);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_DIGEST_KEY:
	    {
		CK_SESSION_HANDLE session;
		CK_OBJECT_HANDLE key;
		READVAR(request_fd, session);
		READVAR(request_fd, key);
		crv = (*pkcs11_function_list->C_DigestKey)(session, key);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_DIGEST_FINAL:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *outData = NULL;
		CK_ULONG outDataLen;
		READVAR(request_fd, session);
		READVAR(request_fd,outDataLen);
		if (outDataLen) {
		    outData = malloc(outDataLen);
		}
		crv = (*pkcs11_function_list->C_DigestFinal)(
			session, outData, &outDataLen);
		WRITEVAR(reply_fd, crv);
		WRITEVAR(reply_fd, outDataLen);
		if (crv == CKR_OK) {
		    write(reply_fd, outData, outDataLen);
		}
	    }
	    break;
	case SC_SIGN_INIT:
	    {
		CK_SESSION_HANDLE session;
		CK_MECHANISM mech;
		CK_OBJECT_HANDLE key;
		READVAR(request_fd, session);
		readmechanism(request_fd, &mech);
		READVAR(request_fd, key);
		crv = (*pkcs11_function_list->C_SignInit)(
			session, &mech, key);
		freemechanism(&mech);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_SIGN:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *inData;
		CK_ULONG inDataLen;
		CK_BYTE *outData = NULL;
		CK_ULONG outDataLen;
		size_t len;
		READVAR(request_fd, session);
		inData=readbuf(request_fd,&len);
		inDataLen = len;
		READVAR(request_fd,outDataLen);
		if (outDataLen) {
		    outData = malloc(outDataLen);
		}
		crv = (*pkcs11_function_list->C_Sign)(
			session, inData, inDataLen, outData, &outDataLen);
		WRITEVAR(reply_fd, crv);
		WRITEVAR(reply_fd, outDataLen);
		if (crv == CKR_OK) {
		    write(reply_fd, outData, outDataLen);
		}
	    }
	    break;
	case SC_SIGN_UPDATE:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *inData;
		CK_ULONG inDataLen;
		size_t len;
		READVAR(request_fd, session);
		inData=readbuf(request_fd,&len);
		inDataLen = len;
		crv = (*pkcs11_function_list->C_SignUpdate)(
			session, inData, inDataLen);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_SIGN_FINAL:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *outData = NULL;
		CK_ULONG outDataLen;
		READVAR(request_fd, session);
		READVAR(request_fd,outDataLen);
		if (outDataLen) {
		    outData = malloc(outDataLen);
		}
		crv = (*pkcs11_function_list->C_SignFinal)(
			session, outData, &outDataLen);
		WRITEVAR(reply_fd, crv);
		WRITEVAR(reply_fd, outDataLen);
		if (crv == CKR_OK) {
		    write(reply_fd, outData, outDataLen);
		}
	    }
	    break;
	case SC_SIGN_RECOVER_INIT:
	    {
		CK_SESSION_HANDLE session;
		CK_MECHANISM mech;
		CK_OBJECT_HANDLE key;
		READVAR(request_fd, session);
		readmechanism(request_fd, &mech);
		READVAR(request_fd, key);
		crv = (*pkcs11_function_list->C_SignRecoverInit)(
			session, &mech, key);
		freemechanism(&mech);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_SIGN_RECOVER:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *inData;
		CK_ULONG inDataLen;
		CK_BYTE *outData = NULL;
		CK_ULONG outDataLen;
		size_t len;
		READVAR(request_fd, session);
		inData=readbuf(request_fd,&len);
		inDataLen = len;
		READVAR(request_fd,outDataLen);
		if (outDataLen) {
		    outData = malloc(outDataLen);
		}
		crv = (*pkcs11_function_list->C_SignRecover)(
			session, inData, inDataLen, outData, &outDataLen);
		WRITEVAR(reply_fd, crv);
		WRITEVAR(reply_fd, outDataLen);
		if (crv == CKR_OK) {
		    write(reply_fd, outData, outDataLen);
		}
	    }
	    break;
	case SC_VERIFY_INIT:
	    {
		CK_SESSION_HANDLE session;
		CK_MECHANISM mech;
		CK_OBJECT_HANDLE key;
		READVAR(request_fd, session);
		readmechanism(request_fd, &mech);
		READVAR(request_fd, key);
		crv = (*pkcs11_function_list->C_VerifyInit)(
			session, &mech, key);
		freemechanism(&mech);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_VERIFY:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *inData;
		CK_ULONG inDataLen;
		CK_BYTE *sigData;
		CK_ULONG sigDataLen;
		size_t len;
		READVAR(request_fd, session);
		inData=readbuf(request_fd,&len);
		inDataLen = len;
		sigData=readbuf(request_fd,&len);
		sigDataLen = len;
		crv = (*pkcs11_function_list->C_Verify)(
			session, inData, inDataLen, sigData, sigDataLen);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_VERIFY_UPDATE:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *inData;
		CK_ULONG inDataLen;
		size_t len;
		READVAR(request_fd, session);
		inData=readbuf(request_fd,&len);
		inDataLen = len;
		crv = (*pkcs11_function_list->C_VerifyUpdate)(
			session, inData, inDataLen);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_VERIFY_FINAL:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *sigData;
		CK_ULONG sigDataLen;
		size_t len;
		READVAR(request_fd, session);
		sigData = readbuf(request_fd,&len);
		sigDataLen = len;
		crv = (*pkcs11_function_list->C_VerifyFinal)(
			session, sigData, sigDataLen);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_VERIFY_RECOVER_INIT:
	    {
		CK_SESSION_HANDLE session;
		CK_MECHANISM mech;
		CK_OBJECT_HANDLE key;
		READVAR(request_fd, session);
		readmechanism(request_fd, &mech);
		READVAR(request_fd, key);
		crv = (*pkcs11_function_list->C_VerifyRecoverInit)(
			session, &mech, key);
		freemechanism(&mech);
		WRITEVAR(reply_fd, crv);
	    }
	    break;
	case SC_VERIFY_RECOVER:
	    {
		CK_SESSION_HANDLE session;
		CK_BYTE *inData;
		CK_ULONG inDataLen;
		CK_BYTE *outData = NULL;
		CK_ULONG outDataLen;
		size_t len;
		READVAR(request_fd, session);
		inData=readbuf(request_fd,&len);
		inDataLen = len;
		READVAR(request_fd,outDataLen);
		if (outDataLen) {
		    outData = malloc(outDataLen);
		}
		crv = (*pkcs11_function_list->C_VerifyRecover)(
			session, inData, inDataLen, outData, &outDataLen);
		WRITEVAR(reply_fd, crv);
		WRITEVAR(reply_fd, outDataLen);
		if (crv == CKR_OK) {
		    write(reply_fd, outData, outDataLen);
		}
	    }
	    break;
	
	/* skip the functions we don't actually need */
	case SC_DIGEST_ENCRYPT_UPDATE:
	case SC_DECRYPT_DIGEST_UPDATE:
	case SC_SIGN_ENCRYPT_UPDATE:
	case SC_DECRYPT_VERIFY_UPDATE:
	case SC_GENERATE_KEY:
	case SC_GENERATE_KEY_PAIR:	/* will need */
	case SC_WRAP_KEY:		/* may need */
	case SC_UNWRAP_KEY:		/* may need */
	case SC_DERIVE_KEY:		/* will need */
	case SC_SEED_RANDOM:
	case SC_GENERATE_RANDOM:
	case SC_GET_FUNCTION_STATUS:
	case SC_CANCEL_FUNCTION:
	case SC_WAIT_FOR_SLOT_EVENT:
	    crv = CKR_FUNCTION_NOT_SUPPORTED;
	    WRITEVAR(reply_fd, crv);
	    break;
	}
    }
    return; /* caller will exit */
}
