/* Written by Richard Christopher, Copyright 2026 NeoTec, LLC */
#define _POSIX_C_SOURCE 200809L
#include "lumberjack.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char path[1024], req[1600], out[2048];
    const char *tmp=getenv("TMPDIR");
    assert(tmp && snprintf(path,sizeof path,"%s/indexed-XXXXXX",tmp)<(int)sizeof path && mkdtemp(path));
    assert(ic_lj_record_v2_abi_version()==2 && ic_lj_record_abi_version()==1);
    snprintf(req,sizeof req,"{\"directory\":\"%s\",\"name\":\"s\",\"principal\":\"owner\",\"durability\":\"local-sync\","
             "\"indexes\":[{\"name\":\"num\",\"kind\":\"item\",\"field\":\"number\",\"type\":\"int64\"}]}",path);
    lj_handle_t h=0;
    assert(ic_lj_record_v2_open(req,strlen(req),&h)==LJ_OK && h);
    const char *cmd="{\"command_id\":\"one\",\"edits\":[{\"op\":\"create\",\"kind\":\"item\"},"
                    "{\"op\":\"field\",\"id\":\"$0\",\"key\":\"number\",\"value\":9007199254740993}]}";
    int64_t len=0;
    assert(ic_lj_record_apply(h,cmd,strlen(cmd),out,sizeof out-1,&len)==LJ_OK);
    const char *q="{\"by\":\"key\",\"index\":\"num\",\"from\":9007199254740993,\"until\":9007199254740994}";
    assert(ic_lj_record_v2_page(h,q,strlen(q),out,sizeof out-1,&len)==LJ_OK);out[len]=0;
    assert(strstr(out,"\"kind\":\"item\"") && ic_lj_record_close(h)==LJ_OK);
    const char *suffixes[]={"s.dat","s.dat.lock","s.dat.log.00000000000000000001"};
    for(size_t i=0;i<3;i++){snprintf(req,sizeof req,"%s/%s",path,suffixes[i]);assert(!unlink(req));}
    assert(!rmdir(path));puts("  record v2: declared int64 index, range and shared apply/close passed");
    return 0;
}
