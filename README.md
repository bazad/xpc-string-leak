xpc-string-leak
===================================================================================================

<!-- Brandon Azad -->


xpc-string-leak is a proof-of-concept exploit for an out-of-bounds memory read in libxpc. This
exploit uses the vulnerability to read out-of-bounds heap memory from diagnosticd, an unsandboxed
root process with the `task_for_pid-allow` entitlement.


The vulnerability
---------------------------------------------------------------------------------------------------

On macOS 10.13.5 and iOS 11.4, the function `_xpc_string_deserialize` does not verify that the
deserialized string is of the proper length before creating an XPC string object with
`_xpc_string_create`. This can lead to a heartbleed-style out-of-bounds heap read if the XPC string
is then serialized into another XPC message.

Here is the implementation of `_xpc_string_deserialize`, decompiled using IDA:

```C
OS_xpc_string *__fastcall _xpc_string_deserialize(OS_xpc_serializer *xserializer)
{
    OS_xpc_string *xstring; // rbx@1
    char *string; // rax@4
    char *contents; // [rsp+8h] [rbp-18h]@1
    size_t size; // [rsp+10h] [rbp-10h]@1 MAPDST

    xstring = 0LL;
    contents = 0LL;
    size = 0LL;
    if ( _xpc_string_get_wire_value(xserializer, (const char **)&contents, &size) )
    {
        if ( contents[size - 1] || (string = _xpc_try_strdup(contents)) == 0LL )
        {
            xstring = 0LL;
        }
        else
        {
            xstring = _xpc_string_create(string, size - 1);
            LOBYTE(xstring->flags) |= 1u;
        }
    }
    return xstring;
}
```

`_xpc_string_deserialize` first calls `_xpc_string_get_wire_value` to retrieve a pointer to the
string data as well as the serialized size of the string, as reported by the string header.
`_xpc_string_deserialize` then checks that the string has a null terminator at the end of its
reported size, but crucially does not check that there is no null terminator earlier in the data.
Finally, it creates a copy of the string on the heap and creates the `OS_xpc_string` object using
`_xpc_string_create`.

Here is the decompiled code for `_xpc_string_create`:

```C
OS_xpc_string *__fastcall _xpc_string_create(const char *string, size_t length)
{
    OS_xpc_string *xstring; // rax@1

    xstring = (OS_xpc_string *)_xpc_base_create(&OBJC_CLASS___OS_xpc_string, 16LL);
    if ( (((_DWORD)length + 4) & 0xFFFFFFFC) + 4 < length )
        _xpc_api_misuse("Unreasonably large string");
    xstring->wire_length = ((length + 4) & 0xFFFFFFFC) + 4;
    xstring->string = string;
    xstring->length = length;
    return xstring;
}
```

`_xpc_string_create` trusts the value of length supplied by `_xpc_string_deserialize` and sets the
appropriate fields in the `OS_xpc_string` object. At this point, the deserialized string may have a
`length` field that is larger than the allocated string data.


Exploitation
---------------------------------------------------------------------------------------------------

Theoretically, this could be used to trigger memory corruption in services that get the length of
the string using `xpc_string_get_length`, but this pattern seems to be uncommon. A less powerful
but more practical exploit strategy is to get the string to be re-serialized and sent back to us,
giving us a heartbleed-style window into the victim process's memory.

This is the implementation of `_xpc_string_serialize`:

```C
void __fastcall _xpc_string_serialize(OS_xpc_string *string, OS_xpc_serializer *serializer)
{
    int type; // [rsp+8h] [rbp-18h]@1
    int size; // [rsp+Ch] [rbp-14h]@1

    type = *((_DWORD *)&OBJC_CLASS___OS_xpc_string + 10);
    _xpc_serializer_append(serializer, &type, 4uLL, 1, 0, 0);
    size = LODWORD(string->length) + 1;
    _xpc_serializer_append(serializer, &size, 4uLL, 1, 0, 0);
    _xpc_serializer_append(serializer, string->string, string->length + 1, 1, 0, 0);
}
```

The `OS_xpc_string`'s `length` parameter is trusted during deserialization, meaning that many bytes
are read from the heap into the serialized message. If the deserialized string was shorter than its
reported length, the message will be filled with out-of-bounds heap data.

We're still limited to exploiting XPC services that reflect some part of the XPC message back to
the client, but this is much more common. For example, on macOS and iOS, diagnosticd is a promising
candidate that also happens to be unsandboxed, root, and has `task_for_pid` privileges. Diagnosticd
is responsible for processing diagnostic messages (for example, messages generated by `os_log`) and
streaming them to clients interested in receiving these messages. By registering to receive our own
diagnostic stream and then sending a diagnostic message with a shorter than expected string, we can
obtain a snapshot of some of the data in diagnosticd's heap, which can aid in getting code
execution in the process.


Usage
---------------------------------------------------------------------------------------------------

To build, run `make`. See the top of the Makefile for various build options.

Run the exploit by specifying the size of the leak on the command line:

	$ ./xpc-string-leak 0x40
	0x2000000000000000 0xe00007ff39bf0992
	0x00007fff56858570 0x00007fff7ed23d0e
	0x0000000000000000 0x0000000000000000
	0x00007fff7ed52be2 0x00007fff7ed29ed6

The leak size must be a multiple of 8 and at least 16.


License
---------------------------------------------------------------------------------------------------

The xpc-string-leak code is released into the public domain. As a courtesy I ask that if you
reference or use any of this code you attribute it to me.


---------------------------------------------------------------------------------------------------
Brandon Azad
