<!-- Written by Richard Christopher, Copyright 2026 NeoTec, LLC -->
# What belongs in the store

Keep code here if the store needs it, or if Corresponder or Intercessor need it from a
store. A route, policy, credential provider or workload fixture used only by an application
belongs in that application's repository, with its tests. A public extension point must
have a generic consumer or test; do not add one merely to preserve a private implementation.

The store owns record compatibility even when the application that wrote the data is absent.
Preserve opaque slots and authenticated storage labels; refuse access to owned scopes rather
than exposing them through a generic route. See [the public extension API](extension-api.md)
for registration, write and read rules, and the compatibility tests.
