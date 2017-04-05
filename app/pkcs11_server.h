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
void pkcs11_client_close(int pid);
   
/*************************************************************************
 *                              The server                               *
 *************************************************************************/
void
pkcs11_server(int request_fd, int reply_fd, 
		CK_FUNCTION_LIST *pkcs11_function_list, void *library_handle);
