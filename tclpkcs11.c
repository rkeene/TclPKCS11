#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#  include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
#ifdef HAVE_DLFCN_H
#  include <dlfcn.h>
#endif
#ifdef HAVE_DL_H
#  include <dl.h>
#endif
#ifdef _WIN32
#  include <windows.h>
#endif
#include <tcl.h>

#if 10 * TCL_MAJOR_VERSION + TCL_MINOR_VERSION >= 86
#  define TCL_INCLUDES_LOADFILE 1
#endif

/* PKCS#11 Definitions for the local platform */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(rv, func) rv func
#define CK_DECLARE_FUNCTION_POINTER(rv, func) rv (CK_PTR func)
#define CK_CALLBACK_FUNCTION(rv, func) CK_DECLARE_FUNCTION_POINTER(rv, func)
#define CK_NULL_PTR ((void *) 0)
#include "pkcs11.h"

#ifndef TCLPKCS11_MAX_HANDLES
#  define TCLPKCS11_MAX_HANDLES 32
#endif

struct tclpkcs11_interpdata {
	/* Handle Hash Table */
	Tcl_HashTable handles;
	unsigned long handles_idx;
};

struct tclpkcs11_handle {
	/* PKCS11 Module Pointers */
	void *base;
	CK_FUNCTION_LIST_PTR pkcs11;

	/* Session Management */
	CK_SLOT_ID session_slot;
	CK_SESSION_HANDLE session;
};

/*
 * Tcl <--> PKCS11 Bridge Functions
 */ 
MODULE_SCOPE Tcl_Obj *tclpkcs11_pkcs11_error(CK_RV errorCode) {
	switch (errorCode) {
		case CKR_OK:
			return(Tcl_NewStringObj("PKCS11_OK OK", -1));
		case CKR_CANCEL:
			return(Tcl_NewStringObj("PKCS11_ERROR CANCEL", -1));
		case CKR_HOST_MEMORY:
			return(Tcl_NewStringObj("PKCS11_ERROR HOST_MEMORY", -1));
		case CKR_SLOT_ID_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR SLOT_ID_INVALID", -1));
		case CKR_GENERAL_ERROR:
			return(Tcl_NewStringObj("PKCS11_ERROR GENERAL_ERROR", -1));
		case CKR_FUNCTION_FAILED:
			return(Tcl_NewStringObj("PKCS11_ERROR FUNCTION_FAILED", -1));
		case CKR_ARGUMENTS_BAD:
			return(Tcl_NewStringObj("PKCS11_ERROR ARGUMENTS_BAD", -1));
		case CKR_NO_EVENT:
			return(Tcl_NewStringObj("PKCS11_ERROR NO_EVENT", -1));
		case CKR_NEED_TO_CREATE_THREADS:
			return(Tcl_NewStringObj("PKCS11_ERROR NEED_TO_CREATE_THREADS", -1));
		case CKR_CANT_LOCK:
			return(Tcl_NewStringObj("PKCS11_ERROR CANT_LOCK", -1));
		case CKR_ATTRIBUTE_READ_ONLY:
			return(Tcl_NewStringObj("PKCS11_ERROR ATTRIBUTE_READ_ONLY", -1));
		case CKR_ATTRIBUTE_SENSITIVE:
			return(Tcl_NewStringObj("PKCS11_ERROR ATTRIBUTE_SENSITIVE", -1));
		case CKR_ATTRIBUTE_TYPE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR ATTRIBUTE_TYPE_INVALID", -1));
		case CKR_ATTRIBUTE_VALUE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR ATTRIBUTE_VALUE_INVALID", -1));
		case CKR_DATA_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR DATA_INVALID", -1));
		case CKR_DATA_LEN_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR DATA_LEN_RANGE", -1));
		case CKR_DEVICE_ERROR:
			return(Tcl_NewStringObj("PKCS11_ERROR DEVICE_ERROR", -1));
		case CKR_DEVICE_MEMORY:
			return(Tcl_NewStringObj("PKCS11_ERROR DEVICE_MEMORY", -1));
		case CKR_DEVICE_REMOVED:
			return(Tcl_NewStringObj("PKCS11_ERROR DEVICE_REMOVED", -1));
		case CKR_ENCRYPTED_DATA_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR ENCRYPTED_DATA_INVALID", -1));
		case CKR_ENCRYPTED_DATA_LEN_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR ENCRYPTED_DATA_LEN_RANGE", -1));
		case CKR_FUNCTION_CANCELED:
			return(Tcl_NewStringObj("PKCS11_ERROR FUNCTION_CANCELED", -1));
		case CKR_FUNCTION_NOT_PARALLEL:
			return(Tcl_NewStringObj("PKCS11_ERROR FUNCTION_NOT_PARALLEL", -1));
		case CKR_FUNCTION_NOT_SUPPORTED:
			return(Tcl_NewStringObj("PKCS11_ERROR FUNCTION_NOT_SUPPORTED", -1));
		case CKR_KEY_HANDLE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_HANDLE_INVALID", -1));
		case CKR_KEY_SIZE_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_SIZE_RANGE", -1));
		case CKR_KEY_TYPE_INCONSISTENT:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_TYPE_INCONSISTENT", -1));
		case CKR_KEY_NOT_NEEDED:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_NOT_NEEDED", -1));
		case CKR_KEY_CHANGED:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_CHANGED", -1));
		case CKR_KEY_NEEDED:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_NEEDED", -1));
		case CKR_KEY_INDIGESTIBLE:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_INDIGESTIBLE", -1));
		case CKR_KEY_FUNCTION_NOT_PERMITTED:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_FUNCTION_NOT_PERMITTED", -1));
		case CKR_KEY_NOT_WRAPPABLE:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_NOT_WRAPPABLE", -1));
		case CKR_KEY_UNEXTRACTABLE:
			return(Tcl_NewStringObj("PKCS11_ERROR KEY_UNEXTRACTABLE", -1));
		case CKR_MECHANISM_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR MECHANISM_INVALID", -1));
		case CKR_MECHANISM_PARAM_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR MECHANISM_PARAM_INVALID", -1));
		case CKR_OBJECT_HANDLE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR OBJECT_HANDLE_INVALID", -1));
		case CKR_OPERATION_ACTIVE:
			return(Tcl_NewStringObj("PKCS11_ERROR OPERATION_ACTIVE", -1));
		case CKR_OPERATION_NOT_INITIALIZED:
			return(Tcl_NewStringObj("PKCS11_ERROR OPERATION_NOT_INITIALIZED", -1));
		case CKR_PIN_INCORRECT:
			return(Tcl_NewStringObj("PKCS11_ERROR PIN_INCORRECT", -1));
		case CKR_PIN_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR PIN_INVALID", -1));
		case CKR_PIN_LEN_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR PIN_LEN_RANGE", -1));
		case CKR_PIN_EXPIRED:
			return(Tcl_NewStringObj("PKCS11_ERROR PIN_EXPIRED", -1));
		case CKR_PIN_LOCKED:
			return(Tcl_NewStringObj("PKCS11_ERROR PIN_LOCKED", -1));
		case CKR_SESSION_CLOSED:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_CLOSED", -1));
		case CKR_SESSION_COUNT:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_COUNT", -1));
		case CKR_SESSION_HANDLE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_HANDLE_INVALID", -1));
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_PARALLEL_NOT_SUPPORTED", -1));
		case CKR_SESSION_READ_ONLY:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_READ_ONLY", -1));
		case CKR_SESSION_EXISTS:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_EXISTS", -1));
		case CKR_SESSION_READ_ONLY_EXISTS:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_READ_ONLY_EXISTS", -1));
		case CKR_SESSION_READ_WRITE_SO_EXISTS:
			return(Tcl_NewStringObj("PKCS11_ERROR SESSION_READ_WRITE_SO_EXISTS", -1));
		case CKR_SIGNATURE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR SIGNATURE_INVALID", -1));
		case CKR_SIGNATURE_LEN_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR SIGNATURE_LEN_RANGE", -1));
		case CKR_TEMPLATE_INCOMPLETE:
			return(Tcl_NewStringObj("PKCS11_ERROR TEMPLATE_INCOMPLETE", -1));
		case CKR_TEMPLATE_INCONSISTENT:
			return(Tcl_NewStringObj("PKCS11_ERROR TEMPLATE_INCONSISTENT", -1));
		case CKR_TOKEN_NOT_PRESENT:
			return(Tcl_NewStringObj("PKCS11_ERROR TOKEN_NOT_PRESENT", -1));
		case CKR_TOKEN_NOT_RECOGNIZED:
			return(Tcl_NewStringObj("PKCS11_ERROR TOKEN_NOT_RECOGNIZED", -1));
		case CKR_TOKEN_WRITE_PROTECTED:
			return(Tcl_NewStringObj("PKCS11_ERROR TOKEN_WRITE_PROTECTED", -1));
		case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR UNWRAPPING_KEY_HANDLE_INVALID", -1));
		case CKR_UNWRAPPING_KEY_SIZE_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR UNWRAPPING_KEY_SIZE_RANGE", -1));
		case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
			return(Tcl_NewStringObj("PKCS11_ERROR UNWRAPPING_KEY_TYPE_INCONSISTENT", -1));
		case CKR_USER_ALREADY_LOGGED_IN:
			return(Tcl_NewStringObj("PKCS11_ERROR USER_ALREADY_LOGGED_IN", -1));
		case CKR_USER_NOT_LOGGED_IN:
			return(Tcl_NewStringObj("PKCS11_ERROR USER_NOT_LOGGED_IN", -1));
		case CKR_USER_PIN_NOT_INITIALIZED:
			return(Tcl_NewStringObj("PKCS11_ERROR USER_PIN_NOT_INITIALIZED", -1));
		case CKR_USER_TYPE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR USER_TYPE_INVALID", -1));
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
			return(Tcl_NewStringObj("PKCS11_ERROR USER_ANOTHER_ALREADY_LOGGED_IN", -1));
		case CKR_USER_TOO_MANY_TYPES:
			return(Tcl_NewStringObj("PKCS11_ERROR USER_TOO_MANY_TYPES", -1));
		case CKR_WRAPPED_KEY_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR WRAPPED_KEY_INVALID", -1));
		case CKR_WRAPPED_KEY_LEN_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR WRAPPED_KEY_LEN_RANGE", -1));
		case CKR_WRAPPING_KEY_HANDLE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR WRAPPING_KEY_HANDLE_INVALID", -1));
		case CKR_WRAPPING_KEY_SIZE_RANGE:
			return(Tcl_NewStringObj("PKCS11_ERROR WRAPPING_KEY_SIZE_RANGE", -1));
		case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
			return(Tcl_NewStringObj("PKCS11_ERROR WRAPPING_KEY_TYPE_INCONSISTENT", -1));
		case CKR_RANDOM_SEED_NOT_SUPPORTED:
			return(Tcl_NewStringObj("PKCS11_ERROR RANDOM_SEED_NOT_SUPPORTED", -1));
		case CKR_RANDOM_NO_RNG:
			return(Tcl_NewStringObj("PKCS11_ERROR RANDOM_NO_RNG", -1));
		case CKR_DOMAIN_PARAMS_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR DOMAIN_PARAMS_INVALID", -1));
		case CKR_BUFFER_TOO_SMALL:
			return(Tcl_NewStringObj("PKCS11_ERROR BUFFER_TOO_SMALL", -1));
		case CKR_SAVED_STATE_INVALID:
			return(Tcl_NewStringObj("PKCS11_ERROR SAVED_STATE_INVALID", -1));
		case CKR_INFORMATION_SENSITIVE:
			return(Tcl_NewStringObj("PKCS11_ERROR INFORMATION_SENSITIVE", -1));
		case CKR_STATE_UNSAVEABLE:
			return(Tcl_NewStringObj("PKCS11_ERROR STATE_UNSAVEABLE", -1));
		case CKR_CRYPTOKI_NOT_INITIALIZED:
			return(Tcl_NewStringObj("PKCS11_ERROR CRYPTOKI_NOT_INITIALIZED", -1));
		case CKR_CRYPTOKI_ALREADY_INITIALIZED:
			return(Tcl_NewStringObj("PKCS11_ERROR CRYPTOKI_ALREADY_INITIALIZED", -1));
		case CKR_MUTEX_BAD:
			return(Tcl_NewStringObj("PKCS11_ERROR MUTEX_BAD", -1));
		case CKR_MUTEX_NOT_LOCKED:
			return(Tcl_NewStringObj("PKCS11_ERROR MUTEX_NOT_LOCKED", -1));
		case CKR_NEW_PIN_MODE:
			return(Tcl_NewStringObj("PKCS11_ERROR NEW_PIN_MODE", -1));
		case CKR_NEXT_OTP:
			return(Tcl_NewStringObj("PKCS11_ERROR NEXT_OTP", -1));
		case CKR_FUNCTION_REJECTED:
			return(Tcl_NewStringObj("PKCS11_ERROR FUNCTION_REJECTED", -1));
		case CKR_VENDOR_DEFINED:
			return(Tcl_NewStringObj("PKCS11_ERROR VENDOR_DEFINED", -1));
	}

	return(Tcl_NewStringObj("PKCS11_ERROR UNKNOWN", -1));
}

MODULE_SCOPE Tcl_Obj *tclpkcs11_bytearray_to_string(const unsigned char *data, unsigned long datalen) {
	unsigned long idx;
	Tcl_Obj *retval;

	retval = Tcl_NewObj();

	if (data == NULL) {
		return(retval);
	}

	for (idx = 0; idx < datalen; idx++) {
		Tcl_AppendObjToObj(retval, Tcl_ObjPrintf("%02x", data[idx]));
	}

	return(retval);
}

MODULE_SCOPE unsigned long tclpkcs11_string_to_bytearray(Tcl_Obj *data, unsigned char *outbuf, unsigned long outbuflen) {
	unsigned long outbufidx = 0;
	char tmpbuf[5];
	char *str;
	int tmpint;
	int tcl_rv;

	if (outbuf == NULL) {
		return(0);
	}

	str = Tcl_GetString(data);
	if (!str) {
		return(0);
	}

	tmpbuf[0] = '0';
	tmpbuf[1] = 'x';
	tmpbuf[4] = '\0';

	for (str = Tcl_GetString(data); *str; str++) {
		tmpbuf[2] = *str;

		str++;
		if (!*str) {
			break;
		}

		tmpbuf[3] = *str;

		tcl_rv = Tcl_GetInt(NULL, tmpbuf, &tmpint);
		if (tcl_rv != TCL_OK) {
			return(0);
		}

		outbuf[outbufidx] = tmpint;
		outbufidx++;

		if (outbufidx >= outbuflen) {
			break;
		}
	}

	return(outbufidx);
}

/* PKCS#11 Mutex functions implementation that use Tcl Mutexes */
MODULE_SCOPE CK_RV tclpkcs11_create_mutex(void **mutex) {
	Tcl_Mutex *retval;

	if (!mutex) {
		return(CKR_GENERAL_ERROR);
	}

	retval = (Tcl_Mutex *) ckalloc(sizeof(*retval));
	memset(retval, 0, sizeof(*retval));

	*mutex = retval;

	return(CKR_OK);
}

MODULE_SCOPE CK_RV tclpkcs11_lock_mutex(void *mutex) {
	if (!mutex) {
		return(CKR_GENERAL_ERROR);
	}

	Tcl_MutexLock(*mutex);

	return(CKR_OK);
}

MODULE_SCOPE CK_RV tclpkcs11_unlock_mutex(void *mutex) {
	if (!mutex) {
		return(CKR_GENERAL_ERROR);
	}

	Tcl_MutexUnlock(*mutex);

	return(CKR_OK);
}

MODULE_SCOPE CK_RV tclpkcs11_destroy_mutex(void *mutex) {
	if (!mutex) {
		return(CKR_GENERAL_ERROR);
	}

	Tcl_MutexFinalize(*mutex);
	ckfree(mutex);

	return(CKR_OK);
}

/* Convience function to start a session if one is not already active */
MODULE_SCOPE int tclpkcs11_start_session(struct tclpkcs11_handle *handle, CK_SLOT_ID slot) {
	CK_SESSION_HANDLE tmp_session;
	CK_RV chk_rv;

	if (handle->session != -1) {
		if (handle->session_slot == slot) {
			return(CKR_OK);
		}

		/* Close the existing session and create a new one */
		chk_rv = handle->pkcs11->C_CloseSession(handle->session);
		handle->session = -1;
		handle->session_slot = -1;
		if (chk_rv != CKR_OK) {
			return(chk_rv);
		}
	}

	chk_rv = handle->pkcs11->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &tmp_session);
	if (chk_rv != CKR_OK) {
		handle->pkcs11->C_CloseSession(handle->session);
		handle->session = -1;
		handle->session_slot = -1;

		return(chk_rv);
	}

	handle->session = tmp_session;
	handle->session_slot = slot;

	return(CKR_OK);
}

MODULE_SCOPE int tclpkcs11_close_session(struct tclpkcs11_handle *handle) {
	CK_RV chk_rv;

	if (handle->session != -1) {
		chk_rv = handle->pkcs11->C_CloseSession(handle->session);
		handle->session = -1;
		handle->session_slot = -1;

		if (chk_rv != CKR_OK) {
			return(chk_rv);
		}
	}

	return(CKR_OK);
}

/*
 * Platform Specific Functions 
 */
MODULE_SCOPE void *tclpkcs11_int_load_module(const char *pathname) {
#if defined(TCL_INCLUDES_LOADFILE)
	int tcl_rv;
	Tcl_LoadHandle *new_handle;

	new_handle = (Tcl_LoadHandle *) ckalloc(sizeof(*new_handle));

	tcl_rv = Tcl_LoadFile(NULL, Tcl_NewStringObj(pathname, -1), NULL, 0, NULL, new_handle);
	if (tcl_rv != TCL_OK) {
		return(NULL);
	}

	return(new_handle);
#elif defined(HAVE_DLOPEN)
	return(dlopen(pathname, RTLD_LAZY | RTLD_LOCAL));
#elif defined(HAVE_SHL_LOAD)
	return(shl_load(pathname, BIND_DEFERRED, 0L));
#elif defined(_WIN32)
	return(LoadLibrary(pathname));
#endif
	return(NULL);
}
MODULE_SCOPE void tclpkcs11_int_unload_module(void *handle) {
#if defined(TCL_INCLUDES_LOADFILE)
	Tcl_LoadHandle *tcl_handle;

	tcl_handle = handle;

	Tcl_FSUnloadFile(NULL, *tcl_handle);

	ckfree(handle);
#elif defined(HAVE_DLOPEN)
	dlclose(handle);
#elif defined(HAVE_SHL_LOAD)
	shl_unload(handle);
#elif defined(_WIN32)
	FreeLibrary(handle);
#endif
	return;
}
MODULE_SCOPE void *tclpkcs11_int_lookup_sym(void *handle, const char *sym) {
#if defined(TCL_INCLUDES_LOADFILE)
	Tcl_LoadHandle *tcl_handle;
	void *retval;

	tcl_handle = handle;

	retval = Tcl_FindSymbol(NULL, *tcl_handle, sym);

	return(retval);
#elif defined(HAVE_DLOPEN)
	return(dlsym(handle, sym));
#elif defined(HAVE_SHL_LOAD)
	void *retval;
	int shl_findsym_ret;

	shl_findsym_ret = shl_findsym(handle, sym, TYPE_PROCEDURE, &retval);
	if (shl_findsym_ret != 0) {
		return(NULL);
	}

	return(retval);
#elif defined(_WIN32)
	return(GetProcAddress(handle, sym));
#endif
	return(NULL);
}

/*
 * Tcl Commands
 */
MODULE_SCOPE int tclpkcs11_load_module(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *new_handle;
	const char *pathname;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle;
	void *handle;
	int is_new_entry;

	CK_C_INITIALIZE_ARGS initargs;
	CK_RV (*getFuncList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
	CK_FUNCTION_LIST_PTR pkcs11_function_list;
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata\n", -1));

		return(TCL_ERROR);
	}

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::loadmodule filename\"", -1));

		return(TCL_ERROR);
	}

	pathname = Tcl_GetString(objv[1]);
	if (!pathname) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid pathname", -1));

		return(TCL_ERROR);
	}

	handle = tclpkcs11_int_load_module(pathname);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to load", -1));

		return(TCL_ERROR);
	}

	getFuncList = tclpkcs11_int_lookup_sym(handle, "C_GetFunctionList");
	if (!getFuncList) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to locate C_GetFunctionList symbol in PKCS#11 module", -1));

		return(TCL_ERROR);
	}

	chk_rv = getFuncList(&pkcs11_function_list);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	if (!pkcs11_function_list) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("C_GetFunctionList returned invalid data", -1));

		return(TCL_ERROR);
	}

	if (!pkcs11_function_list->C_Initialize) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("C_GetFunctionList returned incomplete data", -1));

		return(TCL_ERROR);
	}

	initargs.CreateMutex = tclpkcs11_create_mutex;
	initargs.DestroyMutex = tclpkcs11_destroy_mutex;
	initargs.LockMutex = tclpkcs11_lock_mutex;
	initargs.UnlockMutex = tclpkcs11_unlock_mutex;
	initargs.flags = 0;
	initargs.LibraryFlags = NULL;
	initargs.pReserved = NULL;

	chk_rv = pkcs11_function_list->C_Initialize(&initargs);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle = Tcl_ObjPrintf("pkcsmod%lu", interpdata->handles_idx);
	(interpdata->handles_idx)++;

	tcl_handle_entry = Tcl_CreateHashEntry(&interpdata->handles, (const char *) tcl_handle, &is_new_entry);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to create new hash entry", -1));

		return(TCL_ERROR);
	}

	/* Allocate the per-handle structure */
	new_handle = (struct tclpkcs11_handle *) ckalloc(sizeof(*new_handle));

	/* Initialize the per-handle structure */
	new_handle->base = handle;
	new_handle->pkcs11 = pkcs11_function_list;
	new_handle->session = -1;
	new_handle->session_slot = -1;

	Tcl_SetHashValue(tcl_handle_entry, (ClientData) new_handle);

	Tcl_SetObjResult(interp, tcl_handle);

	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_unload_module(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle;

	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::unloadmodule handle\"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	/* Log out of the PKCS11 module */
	chk_rv = handle->pkcs11->C_Logout(handle->session);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	/* Close the session, cleaning up all the session objects */
	chk_rv = tclpkcs11_close_session(handle);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	/* Ask the PKCS#11 Provider to terminate */
	chk_rv = handle->pkcs11->C_Finalize(NULL);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	/* Delete our hash entry */
	Tcl_DeleteHashEntry(tcl_handle_entry);

	/* Attempt to unload the module */
	tclpkcs11_int_unload_module(handle->base);

	/* Free our allocated handle */
	ckfree((char *) handle);

	Tcl_SetObjResult(interp, Tcl_NewBooleanObj(1));

	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_list_slots(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle;
	Tcl_Obj *ret_list, *curr_item_list, *flags_list, *slot_desc;

	CK_SLOT_ID_PTR slots;
	CK_SLOT_INFO slotInfo;
	CK_TOKEN_INFO tokenInfo;
	CK_ULONG numSlots, currSlot;
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 2) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::listslots handle\"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_GetSlotList(FALSE, NULL, &numSlots);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	slots = (CK_SLOT_ID_PTR) ckalloc(sizeof(*slots) * numSlots);

	chk_rv = handle->pkcs11->C_GetSlotList(FALSE, slots, &numSlots);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	ret_list = Tcl_NewObj();

	for (currSlot = 0; currSlot < numSlots; currSlot++) {
		chk_rv = handle->pkcs11->C_GetSlotInfo(slots[currSlot], &slotInfo);

		curr_item_list = Tcl_NewObj();
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewLongObj(slots[currSlot]));

		flags_list = Tcl_NewObj();

		if (chk_rv != CKR_OK) {
			/* Add an empty string as the token label */
			Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("", 0));

			/* Add the list of existing flags (none) */
			Tcl_ListObjAppendElement(interp, curr_item_list, flags_list);

			/* Add this item to the list */
			Tcl_ListObjAppendElement(interp, ret_list, curr_item_list);

			continue;
		}

		slot_desc = NULL;

		if ((slotInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT) {
			Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("TOKEN_PRESENT", -1));

			chk_rv = handle->pkcs11->C_GetTokenInfo(slots[currSlot], &tokenInfo);

			if (chk_rv == CKR_OK) {
				/* Add the token label as the slot label */
				if (!slot_desc) {
					slot_desc = Tcl_NewStringObj((const char *) tokenInfo.label, 32);
				}

				if ((tokenInfo.flags & CKF_RNG) == CKF_RNG) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("RNG", -1));
				}
				if ((tokenInfo.flags & CKF_WRITE_PROTECTED) == CKF_WRITE_PROTECTED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("WRITE_PROTECTED", -1));
				}
				if ((tokenInfo.flags & CKF_LOGIN_REQUIRED) == CKF_LOGIN_REQUIRED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("LOGIN_REQUIRED", -1));
				}
				if ((tokenInfo.flags & CKF_USER_PIN_INITIALIZED) == CKF_USER_PIN_INITIALIZED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("USER_PIN_INITIALIZED", -1));
				}
				if ((tokenInfo.flags & CKF_RESTORE_KEY_NOT_NEEDED) == CKF_RESTORE_KEY_NOT_NEEDED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("RESTORE_KEY_NOT_NEEDED", -1));
				}
				if ((tokenInfo.flags & CKF_CLOCK_ON_TOKEN) == CKF_CLOCK_ON_TOKEN) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("CLOCK_ON_TOKEN", -1));
				}
				if ((tokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) == CKF_PROTECTED_AUTHENTICATION_PATH) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("PROTECTED_AUTHENTICATION_PATH", -1));
				}
				if ((tokenInfo.flags & CKF_DUAL_CRYPTO_OPERATIONS) == CKF_DUAL_CRYPTO_OPERATIONS) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("DUAL_CRYPTO_OPERATIONS", -1));
				}
				if ((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("TOKEN_INITIALIZED", -1));
				}
				if ((tokenInfo.flags & CKF_SECONDARY_AUTHENTICATION) == CKF_SECONDARY_AUTHENTICATION) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("SECONDARY_AUTHENTICATION", -1));
				}
				if ((tokenInfo.flags & CKF_USER_PIN_COUNT_LOW) == CKF_USER_PIN_COUNT_LOW) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("USER_PIN_COUNT_LOW", -1));
				}
				if ((tokenInfo.flags & CKF_USER_PIN_FINAL_TRY) == CKF_USER_PIN_FINAL_TRY) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("USER_PIN_FINAL_TRY", -1));
				}
				if ((tokenInfo.flags & CKF_USER_PIN_LOCKED) == CKF_USER_PIN_LOCKED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("USER_PIN_LOCKED", -1));
				}
				if ((tokenInfo.flags & CKF_USER_PIN_TO_BE_CHANGED) == CKF_USER_PIN_TO_BE_CHANGED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("USER_PIN_TO_BE_CHANGED", -1));
				}
				if ((tokenInfo.flags & CKF_SO_PIN_COUNT_LOW) == CKF_SO_PIN_COUNT_LOW) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("SO_PIN_COUNT_LOW", -1));
				}
				if ((tokenInfo.flags & CKF_SO_PIN_FINAL_TRY) == CKF_SO_PIN_FINAL_TRY) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("SO_PIN_FINAL_TRY", -1));
				}
				if ((tokenInfo.flags & CKF_SO_PIN_LOCKED) == CKF_SO_PIN_LOCKED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("SO_PIN_LOCKED", -1));
				}
				if ((tokenInfo.flags & CKF_SO_PIN_TO_BE_CHANGED) == CKF_SO_PIN_TO_BE_CHANGED) {
					Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("SO_PIN_TO_BE_CHANGED", -1));
				}
			}
		}

		/* Add additional slot flags */
		if ((slotInfo.flags & CKF_REMOVABLE_DEVICE) == CKF_REMOVABLE_DEVICE) {
			Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("REMOVABLE_DEVICE", -1));
		}
		if ((slotInfo.flags & CKF_HW_SLOT) == CKF_HW_SLOT) {
			Tcl_ListObjAppendElement(interp, flags_list, Tcl_NewStringObj("HW_SLOT", -1));
		}

		if (slot_desc) {
			/* If we found a more descriptive slot description, use it */
			Tcl_ListObjAppendElement(interp, curr_item_list, slot_desc);
		} else {
			/* Add the slot description as the label for tokens with nothing in them */
			Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj((const char *) slotInfo.slotDescription, 32));
		}

		Tcl_ListObjAppendElement(interp, curr_item_list, flags_list);

		Tcl_ListObjAppendElement(interp, ret_list, curr_item_list);
	}

	Tcl_SetObjResult(interp, ret_list);

	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_list_certs(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle, *tcl_slotid;
	long slotid_long;
	Tcl_Obj *obj_label, *obj_cert, *obj_id;
	Tcl_Obj *ret_list, *curr_item_list;
	Tcl_Obj *parse_cert_cmd;
	int tcl_rv;

	CK_SLOT_ID slotid;
	CK_OBJECT_HANDLE hObject;
	CK_ULONG ulObjectCount;
	CK_ATTRIBUTE template[] = {
	                           {CKA_CLASS, NULL, 0},
	                           {CKA_LABEL, NULL, 0},
	                           {CKA_ID, NULL, 0},
	                           {CKA_VALUE, NULL, 0}
	}, *curr_attr;
	CK_ULONG curr_attr_idx;
	CK_OBJECT_CLASS *objectclass;
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::listcerts handle slot\"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];
	tcl_slotid = objv[2];

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, NULL, 0);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	ret_list = Tcl_NewObj();
	while (1) {
		chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &ulObjectCount);
		if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}

		if (ulObjectCount == 0) {
			break;
		}

		if (ulObjectCount != 1) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("FindObjects() returned a weird number of objects.", -1));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}

		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
			curr_attr = &template[curr_attr_idx];
			if (curr_attr->pValue) {
				ckfree(curr_attr->pValue);
			}

			curr_attr->pValue = NULL;
		}

		/* Determine size of values to allocate */
		chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, template, sizeof(template) / sizeof(template[0]));
		if (chk_rv == CKR_ATTRIBUTE_TYPE_INVALID || chk_rv == CKR_ATTRIBUTE_SENSITIVE || chk_rv == CKR_BUFFER_TOO_SMALL) {
			chk_rv = CKR_OK;
		}

		if (chk_rv != CKR_OK) {
			/* Skip this object if we are not able to process it */
			continue;
		}

		/* Allocate values */
		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
			curr_attr = &template[curr_attr_idx];

			if (((CK_LONG) curr_attr->ulValueLen) != ((CK_LONG) -1)) {
				curr_attr->pValue = (void *) ckalloc(curr_attr->ulValueLen);
			}
		}

		/* Populate template values */
		chk_rv = handle->pkcs11->C_GetAttributeValue(handle->session, hObject, template, sizeof(template) / sizeof(template[0]));
		if (chk_rv != CKR_OK && chk_rv != CKR_ATTRIBUTE_SENSITIVE && chk_rv != CKR_ATTRIBUTE_TYPE_INVALID && chk_rv != CKR_BUFFER_TOO_SMALL) {
			/* Return an error if we are unable to process this entry due to unexpected errors */
			for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
				curr_attr = &template[curr_attr_idx];
				if (curr_attr->pValue) {
					ckfree(curr_attr->pValue);
				}
			}

			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			handle->pkcs11->C_FindObjectsFinal(handle->session);

			return(TCL_ERROR);
		}

		/* Extract certificate data */
		obj_label = NULL;
		obj_id = NULL;
		obj_cert = NULL;
		objectclass = NULL;
		for (curr_attr_idx = 0; curr_attr_idx < (sizeof(template) / sizeof(template[0])); curr_attr_idx++) {
			curr_attr = &template[curr_attr_idx];

			if (!curr_attr->pValue) {
				continue;
			}

			switch (curr_attr->type) {
				case CKA_CLASS:
					objectclass = (CK_OBJECT_CLASS *) curr_attr->pValue;

					if (*objectclass != CKO_CERTIFICATE) {
						continue;
					}

					break;
				case CKA_LABEL:
					obj_label = Tcl_NewStringObj(curr_attr->pValue, curr_attr->ulValueLen);
					break;
				case CKA_ID:
					/* Convert the ID into a readable string */
					obj_id = tclpkcs11_bytearray_to_string(curr_attr->pValue, curr_attr->ulValueLen);

					break;
				case CKA_VALUE:
					if (!objectclass) {
						break;
					}

					obj_cert = Tcl_NewByteArrayObj(curr_attr->pValue, curr_attr->ulValueLen);

					break;
			}

			ckfree(curr_attr->pValue);
			curr_attr->pValue = NULL;
		}

		/* Add this certificate data to return list, if all found */
		if (obj_label == NULL || obj_id == NULL || obj_cert == NULL) {
			continue;
		}

		/* Create the current item list */
		curr_item_list = Tcl_NewObj();
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_handle", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, tcl_handle);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_slotid", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, tcl_slotid);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_id", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_id);

		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11_label", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, obj_label);

		/* Call "::pki::x509::parse_cert" to parse the cert */
		parse_cert_cmd = Tcl_NewObj();
		Tcl_ListObjAppendElement(interp, parse_cert_cmd, Tcl_NewStringObj("::pki::x509::parse_cert", -1));
		Tcl_ListObjAppendElement(interp, parse_cert_cmd, obj_cert);

		tcl_rv = Tcl_EvalObjEx(interp, parse_cert_cmd, 0);
		if (tcl_rv != TCL_OK) {
			continue;
		}

		/* Add results of [parse_cert] to our return value */
		Tcl_ListObjAppendList(interp, curr_item_list, Tcl_GetObjResult(interp));

		/*
		 * Override the "type" so that [array set] returns our new
		 * type, but we can still parse through the list and figure
		 * out the real subordinate type
		 */
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("type", -1));
		Tcl_ListObjAppendElement(interp, curr_item_list, Tcl_NewStringObj("pkcs11", -1));

		/* Add the current item to the return value list */
		Tcl_ListObjAppendElement(interp, ret_list, curr_item_list);
	}

	/* Terminate search */
	handle->pkcs11->C_FindObjectsFinal(handle->session);

	/* Return */
	Tcl_SetObjResult(interp, ret_list);

	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_login(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle, *tcl_slotid, *tcl_password;
	long slotid_long;
	char *password;
	int password_len;
	int tcl_rv;

	CK_SLOT_ID slotid;
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 4) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::login handle slot password\"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];
	tcl_slotid = objv[2];
	tcl_password = objv[3];

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	password = Tcl_GetStringFromObj(tcl_password, &password_len);

	chk_rv = handle->pkcs11->C_Login(handle->session, CKU_USER, (CK_UTF8CHAR_PTR) password, password_len);
	switch (chk_rv) {
		case CKR_OK:
		case CKR_USER_ALREADY_LOGGED_IN:
			Tcl_SetObjResult(interp, Tcl_NewBooleanObj(1));

			break;
		case CKR_PIN_INCORRECT:
			Tcl_SetObjResult(interp, Tcl_NewBooleanObj(0));

			break;
		default:
			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			return(TCL_ERROR);
	}

	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_logout(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle, *tcl_slotid;
	long slotid_long;
	int tcl_rv;

	CK_SLOT_ID slotid;
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 3) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::login handle slot\"", -1));

		return(TCL_ERROR);
	}

	tcl_handle = objv[1];
	tcl_slotid = objv[2];

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_Logout(handle->session);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	Tcl_SetObjResult(interp, Tcl_NewBooleanObj(1));

	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_perform_pki(int encrypt, ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *handle;
	unsigned char *input, resultbuf[1024];
	unsigned long tcl_strtobytearray_rv;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *pki_real_cmd;
	Tcl_Obj *tcl_keylist, **tcl_keylist_values, *tcl_keylist_key, *tcl_keylist_val;
	Tcl_Obj *tcl_mode, *tcl_input;
	Tcl_Obj *tcl_handle = NULL, *tcl_slotid = NULL, *tcl_objid = NULL;
	Tcl_Obj *tcl_result;
	long slotid_long;
	int tcl_keylist_llength, idx;
	int input_len;
	CK_ULONG resultbuf_len;
	int tcl_rv;

	CK_SLOT_ID slotid;
	CK_OBJECT_HANDLE hObject;
	CK_ULONG foundObjs;
	CK_OBJECT_CLASS objectclass_pk;
	CK_ATTRIBUTE template[] = {
	                           {CKA_ID, NULL, 0},
	                           {CKA_CLASS, NULL, 0},
	};
	CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL, 0};
	CK_RV chk_rv;

	if (!cd) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid clientdata", -1));

		return(TCL_ERROR);
	}

	if (objc != 4) {
		if (encrypt) {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::encrypt mode input keylist\"", -1));
		} else {
			Tcl_SetObjResult(interp, Tcl_NewStringObj("wrong # args: should be \"pki::pkcs11::decrypt mode input keylist\"", -1));
		}

		return(TCL_ERROR);
	}

	tcl_mode = objv[1];
	tcl_input = objv[2];
	tcl_keylist = objv[3];

	/*
	 * Parse the "keylist" argument and remove the extraneous "type
	 * pkcs11" entry so we can pass it to around as needed
	 *
	 * Also, while we are here, pick out the elements we can
	 */
	/* Duplicate the object so we can modify it */
	if (Tcl_IsShared(tcl_keylist)) {
		tcl_keylist = Tcl_DuplicateObj(tcl_keylist);
	}

	tcl_rv = Tcl_ListObjGetElements(interp, tcl_keylist, &tcl_keylist_llength, &tcl_keylist_values);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	if ((tcl_keylist_llength % 2) != 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("list must have an even number of elements", -1));

		return(TCL_ERROR);
	}

	for (idx = 0; idx < tcl_keylist_llength; idx += 2) {
		tcl_keylist_key = tcl_keylist_values[idx];
		tcl_keylist_val = tcl_keylist_values[idx + 1];

		if (strcmp(Tcl_GetString(tcl_keylist_key), "type") == 0) {
			if (strcmp(Tcl_GetString(tcl_keylist_val), "pkcs11") == 0) {
				/* Remove "type pkcs11" from list */
				tcl_rv = Tcl_ListObjReplace(interp, tcl_keylist, idx, 2, 0, NULL);
			}

			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_handle") == 0) {
			tcl_handle = tcl_keylist_val;

			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_slotid") == 0) {
			tcl_slotid = tcl_keylist_val;

			continue;
		}
		if (strcmp(Tcl_GetString(tcl_keylist_key), "pkcs11_id") == 0) {
			tcl_objid = tcl_keylist_val;

			continue;
		}
	}

	if (strcmp(Tcl_GetString(tcl_mode), "pub") == 0) {
		/* Public Key Operations can be performed by the Tcl PKI Module */
		pki_real_cmd = Tcl_NewObj();

		if (encrypt) {
			Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("::pki::encrypt", -1));
			Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("-nopad", -1));
		} else {
			Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("::pki::decrypt", -1));
			Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("-nounpad", -1));
		}

		Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("-pub", -1));
		Tcl_ListObjAppendElement(interp, pki_real_cmd, Tcl_NewStringObj("-binary", -1));
		Tcl_ListObjAppendElement(interp, pki_real_cmd, tcl_input);
		Tcl_ListObjAppendElement(interp, pki_real_cmd, tcl_keylist);

		return(Tcl_EvalObjEx(interp, pki_real_cmd, 0));
	}

	if (!tcl_handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("could not find element named \"pkcs11_handle\" in keylist", -1));

		return(TCL_ERROR);
	}

	if (!tcl_slotid) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("could not find element named \"pkcs11_slotid\" in keylist", -1));

		return(TCL_ERROR);
	}

	if (!tcl_objid) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("could not find element named \"pkcs11_id\" in keylist", -1));

		return(TCL_ERROR);
	}

	interpdata = (struct tclpkcs11_interpdata *) cd;

	tcl_handle_entry = Tcl_FindHashEntry(&interpdata->handles, (const char *) tcl_handle);
	if (!tcl_handle_entry) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	handle = (struct tclpkcs11_handle *) Tcl_GetHashValue(tcl_handle_entry);
	if (!handle) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("invalid handle", -1));

		return(TCL_ERROR);
	}

	/*
	 * Find the PKCS#11 object ID that cooresponds to this certificate's
	 * private key
	 */
	tcl_rv = Tcl_GetLongFromObj(interp, tcl_slotid, &slotid_long);
	if (tcl_rv != TCL_OK) {
		return(tcl_rv);
	}

	slotid = slotid_long;

	chk_rv = tclpkcs11_start_session(handle, slotid);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	/* CKA_ID */
	template[0].pValue = ckalloc(Tcl_GetCharLength(tcl_objid) / 2);
	tcl_strtobytearray_rv = tclpkcs11_string_to_bytearray(tcl_objid, template[0].pValue, Tcl_GetCharLength(tcl_objid) / 2);
	template[0].ulValueLen = tcl_strtobytearray_rv;

	/* CKA_CLASS */
	objectclass_pk = CKO_PRIVATE_KEY;
	template[1].pValue = &objectclass_pk;
	template[1].ulValueLen = sizeof(objectclass_pk);

	chk_rv = handle->pkcs11->C_FindObjectsInit(handle->session, template, sizeof(template) / sizeof(template[0]));
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		return(TCL_ERROR);
	}

	chk_rv = handle->pkcs11->C_FindObjects(handle->session, &hObject, 1, &foundObjs);
	if (chk_rv != CKR_OK) {
		Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

		handle->pkcs11->C_FindObjectsFinal(handle->session);

		return(TCL_ERROR);
	}

	/* Terminate Search */
	handle->pkcs11->C_FindObjectsFinal(handle->session);

	if (foundObjs < 1) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj("unable to find private key that cooresponds to this certificate", -1));

		return(TCL_ERROR);
	}

	/* Perform the PKI operation (encrypt/decrypt) */
	input = Tcl_GetByteArrayFromObj(tcl_input, &input_len);
	if (encrypt) {
		chk_rv = handle->pkcs11->C_SignInit(handle->session, &mechanism, hObject);
		if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			return(TCL_ERROR);
		}

		resultbuf_len = sizeof(resultbuf);
		chk_rv = handle->pkcs11->C_Sign(handle->session, input, input_len, resultbuf, &resultbuf_len);
		if (chk_rv != CKR_OK) {
			if (chk_rv == CKR_BUFFER_TOO_SMALL) {
				/* Terminate decryption operation */
				handle->pkcs11->C_DecryptFinal(handle->session, NULL, 0);
			}

			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			return(TCL_ERROR);
		}
	} else {
		chk_rv = handle->pkcs11->C_DecryptInit(handle->session, &mechanism, hObject);
		if (chk_rv != CKR_OK) {
			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			return(TCL_ERROR);
		}

		resultbuf_len = sizeof(resultbuf);
		chk_rv = handle->pkcs11->C_Decrypt(handle->session, input, input_len, resultbuf, &resultbuf_len);
		if (chk_rv != CKR_OK) {
			if (chk_rv == CKR_BUFFER_TOO_SMALL) {
				/* Terminate decryption operation */
				handle->pkcs11->C_DecryptFinal(handle->session, NULL, 0);
			}

			Tcl_SetObjResult(interp, tclpkcs11_pkcs11_error(chk_rv));

			return(TCL_ERROR);
		}
	}

	tcl_result = Tcl_NewByteArrayObj(resultbuf, resultbuf_len);

	Tcl_SetObjResult(interp, tcl_result);

	return(TCL_OK);
}

MODULE_SCOPE int tclpkcs11_encrypt(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	return(tclpkcs11_perform_pki(1, cd, interp, objc, objv));
}

MODULE_SCOPE int tclpkcs11_decrypt(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	return(tclpkcs11_perform_pki(0, cd, interp, objc, objv));
}

/*
 * Tcl Loadable Module Initialization
 */
int Tclpkcs11_Init(Tcl_Interp *interp) {
	struct tclpkcs11_interpdata *interpdata;
	Tcl_Command tclCreatComm_ret;
	const char *tclPkgReq_ret;
	int tclPkgProv_ret;

#ifdef USE_TCL_STUBS
	const char *tclInitStubs_ret;

	/* Initialize Stubs */
	tclInitStubs_ret = Tcl_InitStubs(interp, "8.4", 0);
	if (!tclInitStubs_ret) {
		return(TCL_ERROR);
	}
#endif

	tclPkgReq_ret = Tcl_PkgRequire(interp, "pki", "0.1", 0);
	if (!tclPkgReq_ret) {
		return(TCL_ERROR);
	}

	interpdata = (struct tclpkcs11_interpdata *) ckalloc(sizeof(*interpdata));

	/* Initialize InterpData structure */
	Tcl_InitObjHashTable(&interpdata->handles);
	interpdata->handles_idx = 0;

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::loadmodule", tclpkcs11_load_module, interpdata, NULL);
	if (!tclCreatComm_ret) {
		ckfree((char *) interpdata);

		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::unloadmodule", tclpkcs11_unload_module, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::listslots", tclpkcs11_list_slots, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::listcerts", tclpkcs11_list_certs, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::login", tclpkcs11_login, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::logout", tclpkcs11_logout, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::encrypt", tclpkcs11_encrypt, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::decrypt", tclpkcs11_decrypt, interpdata, NULL);
	if (!tclCreatComm_ret) {
		return(TCL_ERROR);
	}

	/* Register PKI handlers */
	Tcl_ObjSetVar2(interp,
	               Tcl_NewStringObj("pki::handlers", -1),
	               Tcl_NewStringObj("pkcs11", -1),
	               Tcl_NewStringObj("::pki::pkcs11::encrypt ::pki::pkcs11::decrypt", -1),
	               TCL_GLOBAL_ONLY
	              );

	tclPkgProv_ret = Tcl_PkgProvide(interp, "pki::pkcs11", "1.0");
	if (tclPkgProv_ret != TCL_OK) {
		return(tclPkgProv_ret);
	}

	return(TCL_OK);
}
