/*
* Version: Build 06
* Written by bombless.
* TimeStamp: 2012-1-1 16:40:57 UTC+8
* File: C:\Users\bombless\Desktop\mod-pe-build6.c
* Compiler: gcc (GCC) 3.4.2 (mingw-special)
* gcc compile command line: gcc -o mod-pe-build6 mod-pe-build6.c
* Also tested for Microsoft Visual C++ :
* (Version 2010, 2008, 2008 Express)
* command line: 
*         cl /TP mod-pe-build6.c
*         link mod-pe-build6.obj
* 
* Encoding: Windows Code Page 936, gbk/gb2312 compatible
* 
*/
//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
/*
* �÷�����Ϊһ���޸ĳ��򡢸�����ӿǵ�Ӧ�ÿ�ܡ�
*/
//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
/*
* Bug Fixed:
*         ԭBuild 04 �ڴ������ļ�ʧ��ʱ��©��pTableָ����ͷŹ���
*         λ�ã�ԭBuild 04 ���ļ� mod-pe-build4.c Դ�ļ�ĩβ
*         
*         �����˼���ڴ�Сʱ�ļ����������190���е�ע��
*/
#include <stdio.h>
#include <windows.h>
#include <malloc.h>


int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        printf("Usage: %s filename \n analyze PE file",argv[0]);
        return -1;
    }
	//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<	��������
    FILE *fpFake = NULL;
	char *fake_file = NULL;
    DWORD sizeFillForHeader = 0;
    DWORD sizeFillForSection = 0;
    DWORD sectionImageSize = 0;
	int sizeCode = 0;
    DWORD wantedIAT_count = 0;
    DWORD wantedIAT_fileOffset = 0;	
    DWORD wantedIAT_sectionOffset = 0;
    int indexForWantedIAT = -1;
    DWORD wantedIAT_RVA = 0;
    DWORD lowestAvailableRva = 0;
    DWORD lowestAvailableFileOffset = 0;
    int indexForImport = -1;
    int i;
    DWORD sizeImport = 0,rvaImport = 0;
    IMAGE_DATA_DIRECTORY *pImportDirectory;
    IMAGE_SECTION_HEADER *pSectionTable;
	DWORD(*pTable)[3];
	char buf[9] = {0};
	DWORD sectionRawEnd = 0;
	long oldPos = 0;
	DWORD import_sectionOffset = 0;
	IMAGE_IMPORT_DESCRIPTOR *pImport;
	char dllName[] = "kernel32.dll";
	char dllShortName[] = "kernel32";
	char buffer[MAX_PATH] = {0};
	DWORD rawOffsetName = 0;
	IMAGE_THUNK_DATA thunk;
	DWORD wantedHeadersSize = 0;
	DWORD wantedImageSize = 0;
	DWORD sizeOfNewHeaders = 0;
	IMAGE_SECTION_HEADER append = {0};
	DWORD fileAlignment = 0;
	DWORD pageAlignment = 0;
	DWORD offsetSectionHeader = 0;
	DWORD imageBase = 0;
	DWORD sectionCount = 0;
	DWORD offsetPeHeader  = 0;
	//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<��������
    FILE *fp = fopen(argv[1],"rb");
    if(!fp)
    {
        perror("unable to open file");
        return -1;
    }
    long fileSize = (fseek(fp,0,SEEK_END),ftell(fp));
    fseek(fp,0,SEEK_SET);
    if(fileSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS))
    {
        goto NotPeFile;
    }
    IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader,1,sizeof dosHeader,fp);
    if(dosHeader.e_magic != 'M' + 'Z' * 256)
    {
        goto NotPeFile;
    }
    offsetPeHeader = dosHeader.e_lfanew;
    if(offsetPeHeader < sizeof(IMAGE_DOS_HEADER))
    {
        goto NotPeFile;
    }
    if(offsetPeHeader + sizeof(IMAGE_NT_HEADERS) >= fileSize)
    {
        goto NotPeFile;
    }
    fseek(fp,offsetPeHeader,SEEK_SET);
    IMAGE_NT_HEADERS ntHeader;
    fread(&ntHeader,1,sizeof ntHeader,fp);
    printf("%d bytes left\n",fileSize - ftell(fp));
    if(ntHeader.Signature != 'P' + 'E' * 256)
    {
        goto NotPeFile;
    }

    if(ntHeader.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
    {
        goto NotPeFile;
    }
    sectionCount = ntHeader.FileHeader.NumberOfSections;
    printf("section count : %u\n",sectionCount);
    if(!sectionCount)
    {
        goto NotPeFile;
    }
    imageBase = ntHeader.OptionalHeader.ImageBase;
    printf("image base : %p\n",imageBase);
    if(imageBase < 65536 || imageBase % 4096)
    {
        goto NotPeFile;
    }
    offsetSectionHeader = ftell(fp);
    printf("section table at RVA %p\n",offsetSectionHeader);
    if(offsetSectionHeader + sectionCount * sizeof(IMAGE_SECTION_HEADER) >= fileSize)
    {
        goto NotPeFile;
    }
    pageAlignment = ntHeader.OptionalHeader.SectionAlignment;
    printf("page-align: %u\n",pageAlignment);
    if(pageAlignment % 4096)
    {
        goto NotPeFile;
    }
    if(ntHeader.OptionalHeader.SizeOfImage % pageAlignment)
    {
        printf("SizeOfImage not aligned\n");
        printf("value %p not aligned to page-align .\n",
                ntHeader.OptionalHeader.SizeOfImage);
        goto NotPeFile;
    }
    fileAlignment = ntHeader.OptionalHeader.FileAlignment;
    printf("file-align: %u\n",fileAlignment);
    if(fileAlignment % 4)
    {
        goto NotPeFile;
    }
    if(ntHeader.OptionalHeader.SizeOfHeaders % fileAlignment)
    {
        printf("SizeOfHeaders not aligned\n");
        printf("value %p not aligned to file-align\n", ntHeader.OptionalHeader.SizeOfHeaders);
        goto NotPeFile;
    }
    pImportDirectory = ntHeader.OptionalHeader.DataDirectory;
    pImportDirectory += IMAGE_DIRECTORY_ENTRY_IMPORT;
    if(pImportDirectory ->Size)
    {
        rvaImport = pImportDirectory ->VirtualAddress;
        sizeImport = pImportDirectory ->Size;
        printf("import table RVA: %p,size %u\n", rvaImport,sizeImport);
    }else{
        printf("no import table\n");
    }
    pSectionTable = (IMAGE_SECTION_HEADER*) malloc(sectionCount * sizeof(IMAGE_SECTION_HEADER));
    fread(pSectionTable,1, sectionCount * sizeof(IMAGE_SECTION_HEADER),fp);
    if(feof(fp))
    {
        free(pSectionTable);
        goto NotPeFile;
    }
    pTable = (DWORD(*)[3])malloc(3 * sizeof(char*) * sectionCount);
    
    //���¸��ݽڱ�������ҵ��������������ռ��ڱ���Ϣ
    for(i = 0; i < sectionCount; ++i)
    {
        memcpy(buf,pSectionTable[i].Name,8);
        printf("��%s\n",buf);
        printf("��С %d �ֽ�\n",pSectionTable[i].Misc.VirtualSize);

        if(!(pSectionTable[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA))
        {
            sectionRawEnd = pSectionTable[i].PointerToRawData;
            sectionRawEnd += pSectionTable[i].SizeOfRawData;
            //�������β������
            sectionRawEnd += (sectionRawEnd % fileAlignment != 0) * (fileAlignment - sectionRawEnd % fileAlignment);
            printf("��ʼ���ļ�ƫ��%6u ,��β���ļ�ƫ�� %-24u #�ļ���С%6d\n",pSectionTable[i].PointerToRawData, sectionRawEnd - 1,fileSize);
            //��Windows������32λ������Գ�����ơ�һ����632ҳ��˵��
            //VirtualSize��ֵ����FileAlignment��ֵ
            //�����͵õ�SizeOfRawData
            //��һ˵�������ԡ�
            //VirtualSize��ֵ��SizeOfRawData��ֵû���κι�ϵ
            //ʵ����SizeOfRawData��ֵ����FileAlignment����,
            //�������ڴ��еĴ�С����VirtualSize��
            //ֵ��SectionAlignment����
            if(sectionRawEnd > fileSize)
            {
                printf("�ڱ����ļ���С�������˳�\n");
                goto ReleaseResourcesAndWarn;
            }
            if(lowestAvailableFileOffset < pSectionTable[i].SizeOfRawData + pSectionTable[i].PointerToRawData)
            {
                lowestAvailableFileOffset = pSectionTable[i].SizeOfRawData + pSectionTable[i].PointerToRawData;
            }
            if(pSectionTable[i].PointerToRawData % fileAlignment)
            {
                printf("�ڱ����ļ���û�ж��뿪ͷ:(����ֵ%u)\n\t ��%u������ֵ��%u\n",fileAlignment,
                    pSectionTable[i].PointerToRawData / fileAlignment,
                    pSectionTable[i].PointerToRawData % fileAlignment);
                goto ReleaseResourcesAndWarn;
            }
            if(pSectionTable[i].SizeOfRawData % fileAlignment)
            {
                printf("�ڱ����ļ���û�ж����β:(����ֵ%u)\n\t ��%u������ֵ��%u\n",fileAlignment,
                    pSectionTable[i].SizeOfRawData / fileAlignment,
                    pSectionTable[i].SizeOfRawData % fileAlignment);
                goto ReleaseResourcesAndWarn;
            }
            if(pSectionTable[i].PointerToRawData <= ftell(fp))
            {
                printf("��ȡ���ļ�λ�ã�%p\n""���Ϸ����ļ�ƫ��ֵ%p:\n", ftell(fp), pSectionTable[i].PointerToRawData);
                printf("Characteristics : %X\n", pSectionTable[i].Characteristics);
                goto ReleaseResourcesAndWarn;
            }
        }
        pTable[i][0] = pSectionTable[i].VirtualAddress;
        pTable[i][1] = pTable[i][0] + pSectionTable[i].Misc.VirtualSize;
        pTable[i][2] = pSectionTable[i].PointerToRawData;
        if(pTable[i][1] % pageAlignment)
        {
            pTable[i][1] += pageAlignment - pTable[i][1] % pageAlignment;
        }
        if(lowestAvailableRva < pTable[i][1])
            lowestAvailableRva = pTable[i][1];
        //pTable[i][1]��ʵ�Ѿ���Խ���߽����һ�ֽ���
        printf("��Χ RVA %p - RVA %p\n",pTable[i][0],pTable[i][1] - 1);
        printf("raw offset %p\n",pSectionTable[i].PointerToRawData);
        
        if(pTable[i][0] <= rvaImport && pTable[i][1] > rvaImport + sizeImport)
        {
            printf("������ڴ˽��С�\n\n");
            indexForImport = i;

        }
    }
    if(sizeImport > pTable[indexForImport][1] - pTable[indexForImport][0])
    {
        printf("��Խ�߽�ĵ���������������ļ�Ӧ���ǲ�������ִ�е�.\n");
        printf("��������Ϊֹ���������.");
        goto ReleaseResourcesAndWarn;
    }
    if(indexForImport == -1 && sizeImport)
        printf("���棺�ڽ���δ�ҵ������\n");
    
    //���¸��ݵ���������������ݣ�����Ҫ��IAT��RVA
    if(indexForImport > -1 && sizeImport)
    {
        oldPos = ftell(fp);
        import_sectionOffset = rvaImport - pTable[indexForImport][0];
        //���ƶ�������
        fseek(fp,pTable[indexForImport][2],SEEK_SET);
        //����ƫ��
        fseek(fp,import_sectionOffset,SEEK_CUR);
        printf("import�ļ�ƫ�ƣ�%u\n",ftell(fp));
        pImport = (IMAGE_IMPORT_DESCRIPTOR*)malloc(sizeImport);
        fread(pImport,1,sizeImport,fp);
        for(i = 0; (i + 1) * sizeof(*pImport) < sizeImport; ++i)
        {
            if(!pImport[i].FirstThunk)break;
            //����ڽڵ�ƫ��ֵ
            rawOffsetName = pImport[i].Name - pTable[indexForImport][0];
            //�ƶ��ļ�ָ�뵽����
            fseek(fp,pTable[indexForImport][2],SEEK_SET);
            fseek(fp,rawOffsetName,SEEK_CUR);
            fread(buffer,1,sizeof dllName,fp);
			
			if (!_strcmpi(buffer, dllName) || !_strcmpi(buffer, dllShortName))
            {
                printf("�ҵ�kernel32.dll��Ӧ�ĵ���������\n");
                wantedIAT_RVA = pImport[i].OriginalFirstThunk;
                printf("wanted IAT RVA %p\n",wantedIAT_RVA);
            }
            printf(" - %s -\n",buffer);
            printf("OriginalFirstThunk %08X\n", pImport[i].OriginalFirstThunk);
            /*
            printf("TimeDateStamp %08X\n",  pImport[i].TimeDateStamp);
            printf("ForwarderChain %08X\n", pImport[i].ForwarderChain);
            printf("Name %08X\n",pImport[i].Name);
            */
            printf("FirstThunk %08X\n\n",pImport[i].FirstThunk);
            /*
            int j;
            for(j = 0; j < sectionCount; ++j)
            {
                if(pTable[j][0] <= pImport[i].OriginalFirstThunk &&  pTable[j][1] >  pImport[i].OriginalFirstThunk + sizeof(IMAGE_THUNK_DATA))
                {
                    printf("%s�ĵ���thunk���ڵ�%u�ڣ� ��Χ RVA %p - RVA %p\n", buffer,j,pTable[j][0],pTable[j][1] - 1);
                    break;
                }
            }*/
            printf("~~~~~~~~~~~~~~~~~~~\n");
        }
        free(pImport);
        fseek(fp,oldPos,SEEK_SET);
    }
    //���¸���IAT���ڵ�RVA���ڽڱ���Ϣ�в���IAT�ľ�����Ϣ
    for(i = 0; i < sectionCount; ++i)
    {
        if(pTable[i][0] <= wantedIAT_RVA && pTable[i][1] > wantedIAT_RVA)
        {
            printf("kernel32.dll��һ��IAT�ڵ�%u��\n",i);
            printf("��Χ RVA %p - RVA %p\n",  pTable[i][0],pTable[i][1] - 1);
            memset(buffer,0,9);
            memcpy(buffer,pSectionTable[i].Name,8);
            if(*buffer)printf("�ڱ�����<%s>\n",buffer);
            wantedIAT_sectionOffset = wantedIAT_RVA - pTable[i][0];
            indexForWantedIAT = i;
            break;
        }
    } 
    //���µ��ļ���ȥ���ҽ��е�IAT
    if(indexForWantedIAT > -1)
    {
        wantedIAT_fileOffset = wantedIAT_sectionOffset + pTable[indexForWantedIAT][2];
        printf("wanted IAT���ļ�ƫ��%p\n",wantedIAT_fileOffset);
        oldPos = ftell(fp);
        fseek(fp,wantedIAT_fileOffset,SEEK_SET);
        //IMAGE_THUNK_DATA thunk;
        fread(&thunk,1,sizeof thunk,fp);
        while(thunk.u1.Function)
        {
            wantedIAT_count += 1;
            fread(&thunk,1,sizeof thunk,fp);
        }
        printf("wanted IAT �� %d ����������\n",wantedIAT_count);
        fseek(fp,oldPos,SEEK_SET);
    }
    //	���¼���NT��ѡͷ��SizeOfHeaders��SizeOfImage�Ƿ���ȷ 
    {
        wantedHeadersSize = offsetSectionHeader + sectionCount * sizeof(IMAGE_SECTION_HEADER);
        printf("�ڱ������%p.\n",wantedHeadersSize);
        wantedHeadersSize +=  (wantedHeadersSize % fileAlignment != 0)  *  (fileAlignment - wantedHeadersSize % fileAlignment);
        printf("SizeOfHeader ӦΪ0x%X,ʵ��Ϊ0x%X.\n",  wantedHeadersSize, ntHeader.OptionalHeader.SizeOfHeaders);
        if(wantedHeadersSize > ntHeader.OptionalHeader.SizeOfHeaders)
        {
            goto ReleaseResourcesAndWarn;
        }
        for( i = 0; i < sectionCount; ++i)
        {
            sectionImageSize += pTable[i][1] - pTable[i][0];
        }
        //��ͷ���Ĵ�С����ѡͷ��sectionAlignment�����϶����
        //���뵽�ܵľ����С��
        //DWORD wantedImageSize;
        wantedImageSize =  sectionImageSize +  (wantedHeadersSize % pageAlignment != 0 ?  (1 + wantedHeadersSize / pageAlignment) *  pageAlignment  : wantedHeadersSize);
        printf("SizeOfImage ӦΪ0x%X,ʵ��Ϊ0x%X.\n",  wantedImageSize,  ntHeader.OptionalHeader.SizeOfImage);
        if(wantedImageSize > ntHeader.OptionalHeader.SizeOfImage)
        {
            goto ReleaseResourcesAndWarn;
        }
    }
    void __invoke__start();
    void __invoke__end();
    sizeCode = (char*)__invoke__end - (char*)__invoke__start;
    if(sizeCode <= 0)
    {
        printf("�����ݵı��������˳�\n");
        free(pTable);
        free(pSectionTable);
        return -1;
    }
	
	printf("----------------sizeCode :%d\n",sizeCode);
    sizeFillForSection =  ((sizeCode % fileAlignment != 0) + sizeCode / fileAlignment) * fileAlignment;
    printf("��չ�ռ�����������%d�ֽ�\n",sizeFillForSection);    
    printf("���濪ʼ���ֹ����µĿ�ִ���ļ�\n");
    {
    //����һ����λ�����һ���ڵ�ĩβ
    //
    //���ǻὫ������뵽����½ڣ�
    //
    //�½ڻḴ��ԭ�еĵ�����������һ�������λ�ã�
    //�Ա��������������������Ŀ��
    //ԭ����Ŀȫ��ָ��ԭ����RVAָ�룬
    //������һ�����kernel32.dll��������ָ���Ƶ�IAT��
    //������Ƶ�IAT��Ϊ���ǵ���LoadLibraryA��GetProcAddress��������
    //
    //���Ƶ�IAT���Լ��Զ�����롢
    //����ԭ�������������һ��������λ���½���
    
    //Ҫʹ�õ����Ļ��һ�û���뵽��ķ�����
    //��ʱ����������Щ����Ҫ�����ķ���
        ntHeader.FileHeader.NumberOfSections += 1;        
        while(ntHeader.OptionalHeader.SizeOfHeaders <  offsetSectionHeader +  (sectionCount + 1) * sizeof(IMAGE_SECTION_HEADER))
        {
            ntHeader.OptionalHeader.SizeOfHeaders += fileAlignment;
            sizeFillForHeader += fileAlignment;
        }
        sizeOfNewHeaders = ntHeader.OptionalHeader.SizeOfHeaders;
        ntHeader.OptionalHeader.SizeOfImage =  
			sectionImageSize + 
			(sizeFillForSection % pageAlignment != 0 ?  (1 + sizeFillForSection / pageAlignment) * pageAlignment  : sizeFillForSection) +
			(sizeOfNewHeaders % pageAlignment != 0 ? (1 + sizeOfNewHeaders / pageAlignment) *  pageAlignment : sizeOfNewHeaders);
		
        for( i = 0; i < sectionCount; ++i)
        {
            if(pSectionTable[i].SizeOfRawData && pSectionTable[i].PointerToRawData)
            {
                pSectionTable[i].PointerToRawData +=  sizeFillForHeader;
            }
        }
    }
    printf("Ϊͷ������%u�ֽڣ�Ϊ�ļ�β����%u�ֽ�.\n", sizeFillForHeader,sizeFillForSection);
    fake_file = (char*)malloc(MAX_PATH + strlen(argv[1]));
    strcpy(fake_file,argv[1]);
    strcat(fake_file,".mod.exe");

    fpFake = fopen(fake_file,"wb");
    free(fake_file);
    if(!fpFake)
    {
        perror("can not create file");
        free(pTable);
        free(pSectionTable);
        fclose(fp);
        return -1;
    }
    fseek(fp,0,SEEK_SET);
    while(ftell(fpFake) < offsetPeHeader)
    {
        fputc(fgetc(fp),fpFake);
    }
    fwrite(&ntHeader,1,sizeof ntHeader,fpFake);
    fseek(fp,sizeof ntHeader,SEEK_CUR);
    fwrite(pSectionTable,1, sectionCount * sizeof(IMAGE_SECTION_HEADER),fpFake);
    free(pTable);
    free(pSectionTable);    
    fseek(fp,sectionCount * sizeof(IMAGE_SECTION_HEADER),SEEK_CUR);

     //���������ӽڱ�
    {
        //IMAGE_SECTION_HEADER append = {0};
        strcpy((char*)append.Name,".append");
        append.Characteristics = IMAGE_SCN_MEM_EXECUTE |  IMAGE_SCN_CNT_CODE |  IMAGE_SCN_MEM_READ;
        append.Misc.VirtualSize = sizeFillForSection;
        append.VirtualAddress = lowestAvailableRva;
        //printf("lowest %p\n",lowestAvailableRva);
        append.PointerToRawData = sizeFillForHeader +  lowestAvailableFileOffset;
        append.SizeOfRawData = sizeFillForSection;
        fwrite(&append,1,sizeof append,fpFake);
        fseek(fp,sizeof append,SEEK_CUR);
    }
    
    //������ļ�ͷ�����˳��ȣ������������������
    while(ftell(fpFake) - ftell(fp) < sizeFillForHeader)
    {
        fputc(0xCC,fpFake);
    }
    //��䣬ֱ������ԭ�ļ������һ�����ýڵ�ĩβ
    while(ftell(fpFake) <  lowestAvailableFileOffset + sizeFillForHeader)
    {
        fputc(fgetc(fp),fpFake);
    }
    printf("д�����ļ���%p , ����%u�ֽ�.\n",  ftell(fpFake),sizeFillForSection);
    fwrite(__invoke__start,1,sizeCode,fpFake);
    sizeFillForSection -= sizeCode;
	while (sizeFillForSection-- > 0){
		fputc(0x90, fpFake);
	}
    printf("д��������䣬���ļ�ƫ��%p.\n",ftell(fpFake));
    
    //��ԭ�ļ���ĩβ���ݰ�ԭ��д�롣
    //��Щ�������������ļ�β��һЩ�������ݣ�
    //�����ǻ����ļ�βѰ��ƫ�Ƶ�
    while(ftell(fp) < sizeFillForHeader + sizeFillForSection + fileSize)
    {
        fputc(fgetc(fp),fpFake);
    }
    fclose(fp);
    printf("д�����ļ������ļ�ƫ��%p.\n",ftell(fpFake));
    fclose(fpFake);
    return 0;
ReleaseResourcesAndWarn:
    printf("ReleaseResourcesAndWarn.\n");
    free(pTable);
    free(pSectionTable);
NotPeFile:
    printf("Not a PE file.\n");
    fclose(fp);
    return -1;
}

struct strTable
{
    char user32_dll[16];
    char MessageBoxA[16];
};
void __main__
(
    struct strTable,
    DWORD imageBase,
    HMODULE (__stdcall*LoadLibraryA)(char*),
    void*(__stdcall*GetProcAddress)(HMODULE,char*),
    DWORD sectionBase
);
void __invoke__start()
{
    DWORD imageBase = 0xAAAAAAAA;
    void **addrLoadLibraryA = (void**)0xBBBBBBBB;
    void **addrGetProcAddress = (void**)0xCCCCCCCC;
    DWORD rvaSection = 0xDDDDDDDD;
    
	printf("22222222222222222222222222222222222222222222222222222222");
    struct strTable str =
    {
        {
            'u','s','e','r','3','2',0
        },
        {
            'M','e','s','s','a','g','e','B','o','x','A',0
        }
    };
	printf(str.MessageBoxA);
	printf(str.user32_dll);
    
    __main__(
        str,
        imageBase,
        (HMODULE(__stdcall*)(char*))*addrLoadLibraryA,
        (void*(__stdcall*)(HMODULE,char*))*addrGetProcAddress,
        imageBase + rvaSection
        );
    return;
}
void __main__
(
    struct strTable str,
    DWORD imageBase,
    HMODULE (__stdcall*_LoadLibraryA)(char*),
    void*(__stdcall*_GetProcAddress)(HMODULE,char*),
    DWORD sectionBase
)
{
	printf(str.user32_dll);
	printf(str.MessageBoxA);
    if(!*str.user32_dll || !*str.MessageBoxA)return;

    if(!_LoadLibraryA)return;
    HMODULE user32_dll = _LoadLibraryA(str.user32_dll);
    if(!user32_dll)return;
    
    if(!_GetProcAddress)return;
    DWORD(__stdcall*MsgBox)(DWORD,char*,char*,DWORD);
    MsgBox =
    (DWORD(__stdcall*)(DWORD,char*,char*,DWORD))
                        _GetProcAddress(user32_dll,str.MessageBoxA);
    if(!MsgBox)return;
    MsgBox(0,
        (char*)(imageBase + ((IMAGE_DOS_HEADER*)imageBase) ->e_lfanew),
        (char*)imageBase,0);
}
void __invoke__end(){}