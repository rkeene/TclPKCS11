#! /usr/bin/env tclsh

set pkcs11_module "/usr/local/lib/libcackey_g.so"

load tclpkcs11.so Tclpkcs11

set handle [::pki::pkcs11::loadmodule $pkcs11_module]
puts "Handle: $handle"

set slots [::pki::pkcs11::listslots $handle]
puts "Slots: $slots"

foreach slotinfo $slots {
	set slotid [lindex $slotinfo 0]
	set slotflags [lindex $slotinfo 1]

	if {[lsearch -exact $slotflags TOKEN_PRESENT] != -1} {
		set token_slotid $slotid
	}
}

if {![info exists token_slotid]} {
	puts stderr "Found no slots with tokens, aborting."

	exit 1
}

set certs [::pki::pkcs11::listcerts $handle $token_slotid]
foreach certinfo $certs {
	set certid [lindex $certinfo 0]
	set cert [lindex $certinfo 1]
}

#::pki::pkcs11::login <handle> <slot> <password>            -> true/false
#::pki::pkcs11::logout <handle> <slot>                      -> true/false
#::pki::pkcs11::sign <handle> <slot> <certId> <data>        -> data
#::pki::pkcs11::decrypt <handle> <slot> <certId> <data>     -> data
#::pki::pkcs11::unloadmoule <handle>                        -> true/false
