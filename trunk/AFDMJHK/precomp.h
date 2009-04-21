/*************************************************************************/
/* Copyright (c) 2001 Printing Communications Associates, Inc. (PCAUSA)  */
/*                           All Rights Reserved.                        */
/*                          http://www.pcausa.com                        */
/*                            ndispim@pcausa.com                         */
/*                                                                       */
/* Module Name:  precomp.h									             */
/*                                                                       */
/* Abstract: Precompiled header for NDIS hooking driver project			 */
/*                                                                       */
/* Environment:                                                          */
/*                                                                       */
/*   Kernel mode, NDIS-hooking driver                                    */
/*                                                                       */
/* Revision History:                                                     */
/*                                                                       */
/*************************************************************************/

#ifndef __PRECOMP_H__
#define __PRECOMP_H__

#define NDIS50 1

// System headers

#include <ntddk.h>
#include <ndis.h>
#include <efilter.h>
#include <afilter.h>
#include <tdi.h>


// Common headers
#include "..\\include\\common.h"
#include "..\\include\\afd.h"
#include "..\\include\\afdstr.h"

// Project headers

#include "types.h"
#include "afdhk.h"
//#include "hook.h"
#include "ioctl.h"
//#include "iodev.h"

#endif