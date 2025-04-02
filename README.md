# MimiLoader
Adapted PE Loader to load a rc4 encrypted mimikatz shellcode into memory with specified arguments before exiting.


(This project was part of my studying towards another project that I want to present as a paper when finished, stay tunned to find out more ^^)

We need to start by understanding how we can load into memory a PE, for that, I took huge reference into building a custom PELoader from the following wonderful posts:

https://www.ambray.dev/writing-a-windows-loader/

And, specially, the following one from captain-woof (HUGE THANKS TO HIM FOR SHARING THIS KIND OF POSTS, GO CHECK OUT MORE OF THEM):

https://captain-woof.medium.com/how-to-write-a-local-pe-loader-from-scratch-for-educational-purposes-30e10cd88abc

### Extracting shellcode encoded

So, first things first, I need to get a clear idea on how my loader needs to work. In this case, I want to load mimikatz directly into memory, I don't want to read any files because the key idea is that mimikatz never touches disk.

For that, we need to convert mimikatz_encoded.exe into shellcode as the following command shows:

```
xxd -i mimikatz_rc4.exe > shellcode.h
```

If we are using the loader itself we would use some kind of encryption/obfuscation methods to bypass static detections, for the sake of keeping things simple, the  mimikatz.exe shellcode loaded has been generated from this RC4 script, feel free to use it or change it.

![image](https://github.com/user-attachments/assets/8024df9d-1b80-4f9a-8c61-236ca2ddb1a1)


### MimiLoader functionality


Now, we can begin with our loader logic.
Our main function will:
- Parse the arguments we specify and add the typicall "exit" mimikatz command to exit as soon as we finish procesing every other command.
- Call the InjectMimikatz Function that will handle the PE Injection
- Free memory after everything is completed.


Our InjectMimikatz:
- Decodes RC4 shellcode
- Read Shellcode into a buffer
- Process the PE File shellcode
- Allocate memory for the inline execution of mimikatz
- Copy the sections into the allocated buffer
- Perform the relocations needed
- Assign the correct permission to the pages
- Register exception handlers
- Fix the command line to point to our arguments
- Jump to the entry point of mimikatz
- Restore the command line


### Usage

Default without arguments = coffee exit

![image](https://github.com/user-attachments/assets/6fce6f9e-c176-43c3-b1c9-e5986810ba93)

(Dummy command example: if the command has spaces you can enclose it in double quotes, doesn't matter the position)

```
.\MimiLoader.exe coffee "lsadump::trust /patch" coffee
```

![image](https://github.com/user-attachments/assets/ed864b68-c308-4723-b60d-508a3d4998bd)


```
.\MimiLoader.exe privilege::debug token::elevate coffee
```

![image](https://github.com/user-attachments/assets/da4e34f6-eb7b-4879-a396-be5a853adf54)


![image](https://github.com/user-attachments/assets/ffa56cf8-91ad-4d6a-a85e-c7d5bbd311cd)



