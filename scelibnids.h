/*
sceLibcNids and sceLibmNids
from UCJS-10111
*/

#ifndef __SCELIBNIDS_H__
#define __SCELIBNIDS_H__


struct SyslibEntry
{
	unsigned int nid;
	const char* name;
};

extern const SyslibEntry g_sceLibc[];
extern const size_t g_sceLibc_cnt;

extern const SyslibEntry g_sceLibm[];
extern const size_t g_sceLibm_cnt;

extern const SyslibEntry g_syslib[];
extern const size_t g_syslib_cnt;


#endif // __SCELIBNIDS_H__
