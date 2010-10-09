#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <tcl.h>

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
	void *base;
	CK_FUNCTION_LIST_PTR pkcs11;
};

static int tclpkcs11_load_module(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *CONST objv[]) {
	CK_RV (*getFuncList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
	CK_FUNCTION_LIST_PTR pkcs11_function_list;
	struct tclpkcs11_interpdata *interpdata;
	struct tclpkcs11_handle *new_handle;
	const char *pathname;
	Tcl_HashEntry *tcl_handle_entry;
	Tcl_Obj *tcl_handle;
	void *handle;
	char handle_buf[32];
	int snprintf_ret;
	int is_new_entry;
	CK_RV getFuncList_ret;

	if (!cd) {
		Tcl_SetResult(interp, "invalid clientdata\n", TCL_STATIC);

		return(TCL_ERROR);
	}

	if (objc != 2) {
		Tcl_SetResult(interp, "wrong # args: should be \"pki::pkcs11::loadmodule filename\"", TCL_STATIC);

		return(TCL_ERROR);
	}

	pathname = Tcl_GetString(objv[1]);
	if (!pathname) {
		Tcl_SetResult(interp, "invalid pathname", TCL_STATIC);

		return(TCL_ERROR);
	}

	handle = dlopen(pathname, RTLD_LAZY | RTLD_LOCAL);
	if (!handle) {
		Tcl_SetResult(interp, "unable to load", TCL_STATIC);

		return(TCL_ERROR);
	}

	getFuncList = dlsym(handle, "C_GetFunctionList");
	if (!getFuncList) {
		Tcl_SetResult(interp, "unable to locate C_GetFunctionList symbol in PKCS#11 module", TCL_STATIC);

		return(TCL_ERROR);
	}

	getFuncList_ret = getFuncList(&pkcs11_function_list);
	if (getFuncList_ret != CKR_OK) {
		Tcl_SetResult(interp, "C_GetFunctionList returned in failure", TCL_STATIC);


		return(TCL_ERROR);
	}

	if (!pkcs11_function_list) {
		Tcl_SetResult(interp, "C_GetFunctionList returned invalid data", TCL_STATIC);

		return(TCL_ERROR);
	}

	if (!pkcs11_function_list->C_Initialize) {
		Tcl_SetResult(interp, "C_GetFunctionList returned incomplete data", TCL_STATIC);

		return(TCL_ERROR);
	}

	interpdata = (struct tclpkcs11_interpdata *) cd;

	snprintf_ret = snprintf(handle_buf, sizeof(handle_buf), "pkcsmod%lu", interpdata->handles_idx);
	(interpdata->handles_idx)++;

	if (snprintf_ret >= sizeof(handle_buf)) {
		snprintf_ret = sizeof(handle_buf) - 1;
	}

	tcl_handle = Tcl_NewStringObj(handle_buf, snprintf_ret);
	if (!tcl_handle) {
		Tcl_SetResult(interp, "unable to create new string obj", TCL_STATIC);

		return(TCL_ERROR);
	}

	tcl_handle_entry = Tcl_CreateHashEntry(&interpdata->handles, (const char *) tcl_handle, &is_new_entry);
	if (!tcl_handle_entry) {
		Tcl_SetResult(interp, "unable to create new hash entry", TCL_STATIC);

		return(TCL_ERROR);
	}

	new_handle = malloc(sizeof(*new_handle));
	if (!new_handle) {
		Tcl_SetResult(interp, "unable to allocate internal handle structure", TCL_STATIC);
		return(TCL_ERROR);
	}

	new_handle->base = handle;
	new_handle->pkcs11 = pkcs11_function_list;

	Tcl_SetHashValue(tcl_handle_entry, (ClientData) new_handle);

	Tcl_SetObjResult(interp, tcl_handle);

	return(TCL_OK);
}

int Tclpkcs11_Init(Tcl_Interp *interp) {
	struct tclpkcs11_interpdata *interpdata;
	Tcl_Command tclCreatComm_ret;
	int tclPkgProv_ret;

	interpdata = malloc(sizeof(*interpdata));
	if (!interpdata) {
		Tcl_SetResult(interp, "failed to allocate interpdata structure", TCL_STATIC);

		return(TCL_ERROR);
	}

	/* Initialize InterpData structure */
	Tcl_InitObjHashTable(&interpdata->handles);
	interpdata->handles_idx = 0;

	tclCreatComm_ret = Tcl_CreateObjCommand(interp, "pki::pkcs11::loadmodule", tclpkcs11_load_module, interpdata, NULL);
	if (!tclCreatComm_ret) {
		Tcl_SetResult(interp, "failed to create required commands", TCL_STATIC);

		return(TCL_ERROR);
	}

	tclPkgProv_ret = Tcl_PkgProvide(interp, "pki::pkcs11", "1.0");
	if (tclPkgProv_ret != TCL_OK) {
		Tcl_SetResult(interp, "failed to provide package pki::pkcs11", TCL_STATIC);

		return(tclPkgProv_ret);
	}

	return(TCL_OK);
}
