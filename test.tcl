#! /usr/bin/env tclsh

lappend auto_path [file join [pwd] work lib]

set pkcs11_module "/usr/local/lib/libcackey.so"

load tclpkcs11.so Tclpkcs11

set handle [pki::pkcs11::loadmodule $pkcs11_module]
puts "Handle: $handle"

set slots [pki::pkcs11::listslots $handle]
puts "Slots: $slots"

foreach slotinfo $slots {
	set slotid [lindex $slotinfo 0]
	set slotlabel [lindex $slotinfo 1]
	set slotflags [lindex $slotinfo 2]

	if {[lsearch -exact $slotflags TOKEN_PRESENT] != -1} {
		set token_slotlabel $slotlabel
		set token_slotid $slotid
	}
}

if {![info exists token_slotid]} {
	puts stderr "Found no slots with tokens, aborting."

	exit 1
}

set certs [pki::pkcs11::listcerts $handle $token_slotid]
puts "Found [llength $certs] certificates"

set orig "TestMsg"
foreach certinfo_list $certs {
	unset -nocomplain certinfo
	array set certinfo $certinfo_list
	puts "Cert: $certinfo(pkcs11_label) / $certinfo(subject)"

	set cipher [pki::encrypt -binary -pub $orig $certinfo_list]

	if {[catch {
		set plain  [pki::decrypt -binary -priv $cipher $certinfo_list]
	} err]} {
		if {$err == "PKCS11_ERROR USER_NOT_LOGGED_IN"} {
			# Login and try it again...
			puts -nonewline " *** ENTER PIN: "
			flush stdout

			gets stdin password
			pki::pkcs11::login $handle $token_slotid $password

			set plain  [pki::decrypt -binary -priv $cipher $certinfo_list]
		}
	}

	if {$plain != $orig} {
		puts "Decryption error!  Expected \"$orig\", got \"$plain\""

		exit 1
	}

	set cipher [pki::encrypt -binary -priv $orig $certinfo_list]
	set plain  [pki::decrypt -binary -pub $cipher $certinfo_list]

	set sig    [pki::sign $orig $certinfo_list]
	set verify [pki::verify $sig $orig $certinfo_list]

	if {!$verify} {
		puts "Signature verification error!"

		exit 1
	}
}

pki::pkcs11::unloadmodule $handle
