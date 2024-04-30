#pragma once

//https://source.winehq.org/source/dlls/advapi32/crypt_arc4.c

#include "headers.h"
#include "ntstatus.h"
#include "defs.h"
#define WIN32_NO_STATUS

typedef struct tag_arc4_info {
    unsigned char state[256];
    unsigned char x, y;
} arc4_info;

static void arc4_init(arc4_info* a4i, const BYTE* key, unsigned int keyLen)
{
    unsigned int keyIndex = 0, stateIndex = 0;
    unsigned int i, a;

    a4i->x = a4i->y = 0;

    for (i = 0; i < 256; i++)
        a4i->state[i] = i;

    for (i = 0; i < 256; i++)
    {
        a = a4i->state[i];
        stateIndex += key[keyIndex] + a;
        stateIndex &= 0xff;
        a4i->state[i] = a4i->state[stateIndex];
        a4i->state[stateIndex] = a;
        if (++keyIndex >= keyLen)
            keyIndex = 0;
    }
}

static void arc4_ProcessString(arc4_info* a4i, BYTE* inoutString, unsigned int length)
{
    BYTE* const s = a4i->state;
    unsigned int x = a4i->x;
    unsigned int y = a4i->y;
    unsigned int a, b;

    while (length--)
    {
        x = (x + 1) & 0xff;
        a = s[x];
        y = (y + a) & 0xff;
        b = s[y];
        s[x] = b;
        s[y] = a;
        *inoutString++ ^= s[(a + b) & 0xff];
    }

    a4i->x = x;
    a4i->y = y;
}

/******************************************************************************
 * SystemFunction032  [ADVAPI32.@]
 *
 * Encrypts a string data using ARC4
 *
 * PARAMS
 *   data    [I/O] data to encrypt
 *   key     [I] key data
 *
 * RETURNS
 *  Success: STATUS_SUCCESS
 *  Failure: STATUS_UNSUCCESSFUL
 *
 * NOTES
 *  see http://web.it.kth.se/~rom/ntsec.html#crypto-strongavail
 */
NTSTATUS WINAPI SystemFunction032(struct ustring* data, const struct ustring* key)
{
    arc4_info a4i;

    arc4_init(&a4i, key->Buffer, key->Length);
    arc4_ProcessString(&a4i, data->Buffer, data->Length);

    return STATUS_SUCCESS;
}