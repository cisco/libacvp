/*
 * run the module under test in another process. This code marshals arguements
 * back and forth
 */
	
/*************************************************************************
 *                              The client                               *
 *************************************************************************/
/* get the client side function list */
CK_FUNCTION_LIST * pkcs11_client_get_function_list(void);

/* squirrel away the pipe file descriptors */
void pkcs11_client_set_fd(int request_fd, int reply_fd);

/* close down the server */
int pkcs11_client_close(int pid);

#ifdef ENABLE_NSS_DRBG
/* FREEBL direct functions for testing the drbg */    
SECStatus freebl_drbg_instantiate(const PRUint8 *entropy,
                                   unsigned int entropy_len,
                                   const PRUint8 *nonce,
                                   unsigned int nonce_len,
                                   const PRUint8 *personal_string,
                                   unsigned int ps_len);

SECStatus freebl_drbg_reseed(const PRUint8 *entropy,
                               unsigned int entropy_len,
                               const PRUint8 *additional,
                               unsigned int additional_len);

SECStatus freebl_drbg_generate(PRUint8 *bytes,
                                 unsigned int bytes_len,
                                 const PRUint8 *additional,
                                 unsigned int additional_len);

SECStatus freebl_drbg_uninstantiate();
#endif
   
/*************************************************************************
 *                              The server                               *
 *************************************************************************/
void
pkcs11_server(int request_fd, int reply_fd,
	const CK_FUNCTION_LIST *pkcs11_function_list, 
	const FREEBLVector *freebl_function_list, 
	void *library_handle, void *freebl_library_handle);
