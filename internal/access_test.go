// Written by Richard Christopher, Copyright 2026 NeoTec, LLC
package internal

import (
 "testing"
 "github.com/NeoTecDigital/LumberJack/internal/core"
)

func TestAccessPreviewScopesAndIndependentSources(t *testing.T) {
 s:=setupTestForest(t)
 s.forest.Users=append(s.forest.Users,core.User{ID:"bob",Username:"bob",Permissions:[]core.Permission{core.ReadPermission}})
 token,_,err:=s.mintApplicationSession("admin");if err!=nil{t.Fatal(err)}
 create:=func(parent,title string) string {return workTestCommand(t,s,"admin",workCommand{Command:"create",Path:parent,Title:title,ClientID:title,Kind:"idea"},200)["path"].(string)}
 branch:=create("root","branch"); child:=create(branch,"child"); unrelated:=create("root","unrelated")
 request:=map[string]interface{}{"action":"grant","path":branch,"username":"bob","scope":"ongoing","permission":0}
 preview:=conversationCall(t,s,token,"POST","/access/preview",request,200)
 conversationCall(t,s,token,"POST","/access/apply",request,409)
 request["revision"]=preview["revision"]
 applied:=conversationCall(t,s,token,"POST","/access/apply",request,200)
 a,_:=s.getNodeFromPath(child);if !a.CheckPermission("bob",core.ReadPermission){t.Fatal("branch omitted existing child")}
 future:=create(branch,"future"); b,_:=s.getNodeFromPath(future);if !b.CheckPermission("bob",core.ReadPermission){t.Fatal("ongoing branch omitted future child")}
 other,_:=s.getNodeFromPath(unrelated);if other.CheckPermission("bob",core.ReadPermission){t.Fatal("branch leaked unrelated work")}
 // A second, item-specific source survives revocation of the branch grant.
 specific:=map[string]interface{}{"action":"grant","path":child,"username":"bob","scope":"item","permission":1}
 p:=conversationCall(t,s,token,"POST","/access/preview",specific,200);specific["revision"]=p["revision"]
 conversationCall(t,s,token,"POST","/access/apply",specific,200)
 revoke:=map[string]interface{}{"action":"revoke","path":branch,"grant_id":applied["grant_id"]}
 p=conversationCall(t,s,token,"POST","/access/preview",revoke,200);revoke["revision"]=p["revision"]
 conversationCall(t,s,token,"POST","/access/apply",revoke,200)
 if !a.CheckPermission("bob",core.WritePermission)||b.CheckPermission("bob",core.ReadPermission){t.Fatal("revocation ignored independent sources")}
 // Existing descendants are a snapshot; future children stay private.
 snapshot:=map[string]interface{}{"action":"grant","path":branch,"username":"bob","scope":"existing","permission":0}
 p=conversationCall(t,s,token,"POST","/access/preview",snapshot,200);snapshot["revision"]=p["revision"]
 conversationCall(t,s,token,"POST","/access/apply",snapshot,200)
 after:=create(branch,"after-snapshot");n,_:=s.getNodeFromPath(after);if n.CheckPermission("bob",core.ReadPermission){t.Fatal("snapshot included a future child")}
}
