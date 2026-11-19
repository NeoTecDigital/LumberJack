/* Written by Richard Christopher, Copyright 2026 NeoTec, LLC */
#define _POSIX_C_SOURCE 200809L
#include "lumberjack.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char dir[1024], req[1400], out[2048] = {0};
    const char *tmp = getenv("TMPDIR");
    assert(tmp && snprintf(dir, sizeof(dir), "%s/records-XXXXXX", tmp) < (int)sizeof(dir));
    assert(mkdtemp(dir));
    assert(ic_lj_record_abi_version() == 1 && ic_lj_abi_version() == LJ_ABI_VERSION);
    snprintf(req, sizeof(req), "{\"directory\":\"%s\",\"name\":\"s\",\"principal\":\"owner\",\"durability\":\"local-sync\"}",dir);
    lj_handle_t h=0;
    assert(ic_lj_record_open(req,strlen(req),&h)==LJ_OK && h!=0);
    const char *cmd="{\"command_id\":\"one\",\"edits\":[{\"op\":\"create\",\"kind\":\"ticket\"}]}";
    int64_t n=0;
    assert(ic_lj_record_apply(h,cmd,strlen(cmd),out,1,&n)==LJ_TRUNCATED && n>1);
    assert(ic_lj_record_apply(h,cmd,strlen(cmd),out,sizeof(out)-1,&n)==LJ_OK);
    out[n]=0; assert(strstr(out,"\"sequence\":1") && strstr(out,"\"created\""));
    const char *page="{\"by\":\"kind\",\"kind\":\"ticket\"}";
    assert(ic_lj_record_page(h,page,strlen(page),out,sizeof(out)-1,&n)==LJ_OK);
    out[n]=0;assert(strstr(out,"ticket"));
    assert(ic_lj_record_close(h)==LJ_OK);
    assert(ic_lj_record_page(h,page,strlen(page),out,sizeof(out)-1,&n)==LJ_BAD_HANDLE);
    char p[1152];const char *suffixes[]={"s.dat","s.dat.lock","s.dat.log.00000000000000000001"};
    for(size_t i=0;i<sizeof(suffixes)/sizeof(suffixes[0]);i++){snprintf(p,sizeof(p),"%s/%s",dir,suffixes[i]);assert(unlink(p)==0);}
    assert(rmdir(dir)==0);
    puts("  record profile: version, open, apply, retry, page and close passed");
    return 0;
}
