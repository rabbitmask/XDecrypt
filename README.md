# XDecrypt
Xmanager Decrypt Tools.

# Reference:  
> https://github.com/HyperSine/how-does-Xmanager-encrypt-password/blob/master/doc/how-does-Xmanager-encrypt-password.md

# Usage:
```
    __  __    ___                           _
    \ \/ /   /   \___  ___ _ __ _   _ _ __ | |_
     \  /   / /\ / _ \/ __| '__| | | | '_ \| __|
     /  \  / /_//  __/ (__| |  | |_| | |_) | |_
    /_/\_\/___,' \___|\___|_|   \__, | .__/ \__|
                                |___/|_|


    # xa: For session file version < 5.1 .Encrypted by XShell
        usage: XDecrypt xa [ciphertext]

    # xb: For session file version < 5.1 .Encrypted by XFtp
        usage: XDecrypt xb [ciphertext]

    # xc: For session file version == 5.1 OR 5.2
        usage: XDecrypt xc [SID] [ciphertext]

    # xd: For session file version > 5.2
        usage: XDecrypt xd [USERNAME] [SID] [ciphertext]

    # xe: For session file version > 5.1 where user has set a master password
        usage: XDecrypt xe [PASSWORD] [ciphertext]

```
