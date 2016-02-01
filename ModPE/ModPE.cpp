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
* 用法：作为一个修改程序、给程序加壳的应用框架。
*/
//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
/*
* Bug Fixed:
*         原Build 04 在创建新文件失败时遗漏了pTable指针的释放工作
*         位置：原Build 04 的文件 mod-pe-build4.c 源文件末尾
*         
*         修正了计算节大小时的几个错误，详见190行中的注释
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
	//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<	声明变量
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
	//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<代码正文
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
    
    //以下根据节表的数据找导入描述符表，并收集节表信息
    for(i = 0; i < sectionCount; ++i)
    {
        memcpy(buf,pSectionTable[i].Name,8);
        printf("节%s\n",buf);
        printf("大小 %d 字节\n",pSectionTable[i].Misc.VirtualSize);

        if(!(pSectionTable[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA))
        {
            sectionRawEnd = pSectionTable[i].PointerToRawData;
            sectionRawEnd += pSectionTable[i].SizeOfRawData;
            //下面给结尾量对齐
            sectionRawEnd += (sectionRawEnd % fileAlignment != 0) * (fileAlignment - sectionRawEnd % fileAlignment);
            printf("开始于文件偏移%6u ,结尾于文件偏移 %-24u #文件大小%6d\n",pSectionTable[i].PointerToRawData, sectionRawEnd - 1,fileSize);
            //《Windows环境下32位汇编语言程序设计》一书中632页里说，
            //VirtualSize的值按照FileAlignment的值
            //对齐后就得到SizeOfRawData
            //这一说具有误导性。
            //VirtualSize的值与SizeOfRawData的值没有任何关系
            //实际上SizeOfRawData的值按照FileAlignment对齐,
            //而节在内存中的大小根据VirtualSize的
            //值按SectionAlignment对齐
            if(sectionRawEnd > fileSize)
            {
                printf("节表与文件大小不符，退出\n");
                goto ReleaseResourcesAndWarn;
            }
            if(lowestAvailableFileOffset < pSectionTable[i].SizeOfRawData + pSectionTable[i].PointerToRawData)
            {
                lowestAvailableFileOffset = pSectionTable[i].SizeOfRawData + pSectionTable[i].PointerToRawData;
            }
            if(pSectionTable[i].PointerToRawData % fileAlignment)
            {
                printf("节表在文件中没有对齐开头:(对齐值%u)\n\t 比%u倍对齐值多%u\n",fileAlignment,
                    pSectionTable[i].PointerToRawData / fileAlignment,
                    pSectionTable[i].PointerToRawData % fileAlignment);
                goto ReleaseResourcesAndWarn;
            }
            if(pSectionTable[i].SizeOfRawData % fileAlignment)
            {
                printf("节表在文件中没有对齐结尾:(对齐值%u)\n\t 比%u倍对齐值多%u\n",fileAlignment,
                    pSectionTable[i].SizeOfRawData / fileAlignment,
                    pSectionTable[i].SizeOfRawData % fileAlignment);
                goto ReleaseResourcesAndWarn;
            }
            if(pSectionTable[i].PointerToRawData <= ftell(fp))
            {
                printf("读取到文件位置：%p\n""不合法的文件偏移值%p:\n", ftell(fp), pSectionTable[i].PointerToRawData);
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
        //pTable[i][1]其实已经跨越到边界的下一字节了
        printf("范围 RVA %p - RVA %p\n",pTable[i][0],pTable[i][1] - 1);
        printf("raw offset %p\n",pSectionTable[i].PointerToRawData);
        
        if(pTable[i][0] <= rvaImport && pTable[i][1] > rvaImport + sizeImport)
        {
            printf("导入表在此节中。\n\n");
            indexForImport = i;

        }
    }
    if(sizeImport > pTable[indexForImport][1] - pTable[indexForImport][0])
    {
        printf("跨越边界的导入描述符表，这个文件应该是不能正常执行的.\n");
        printf("分析到此为止，程序结束.");
        goto ReleaseResourcesAndWarn;
    }
    if(indexForImport == -1 && sizeImport)
        printf("警告：在节中未找到导入表\n");
    
    //以下根据导入描述符表的内容，找需要的IAT的RVA
    if(indexForImport > -1 && sizeImport)
    {
        oldPos = ftell(fp);
        import_sectionOffset = rvaImport - pTable[indexForImport][0];
        //先移动到节首
        fseek(fp,pTable[indexForImport][2],SEEK_SET);
        //节首偏移
        fseek(fp,import_sectionOffset,SEEK_CUR);
        printf("import文件偏移：%u\n",ftell(fp));
        pImport = (IMAGE_IMPORT_DESCRIPTOR*)malloc(sizeImport);
        fread(pImport,1,sizeImport,fp);
        for(i = 0; (i + 1) * sizeof(*pImport) < sizeImport; ++i)
        {
            if(!pImport[i].FirstThunk)break;
            //相对于节的偏移值
            rawOffsetName = pImport[i].Name - pTable[indexForImport][0];
            //移动文件指针到节首
            fseek(fp,pTable[indexForImport][2],SEEK_SET);
            fseek(fp,rawOffsetName,SEEK_CUR);
            fread(buffer,1,sizeof dllName,fp);
			
			if (!_strcmpi(buffer, dllName) || !_strcmpi(buffer, dllShortName))
            {
                printf("找到kernel32.dll对应的导入描述符\n");
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
                    printf("%s的导入thunk表在第%u节， 范围 RVA %p - RVA %p\n", buffer,j,pTable[j][0],pTable[j][1] - 1);
                    break;
                }
            }*/
            printf("~~~~~~~~~~~~~~~~~~~\n");
        }
        free(pImport);
        fseek(fp,oldPos,SEEK_SET);
    }
    //以下根据IAT所在的RVA，在节表信息中查找IAT的具体信息
    for(i = 0; i < sectionCount; ++i)
    {
        if(pTable[i][0] <= wantedIAT_RVA && pTable[i][1] > wantedIAT_RVA)
        {
            printf("kernel32.dll的一个IAT在第%u节\n",i);
            printf("范围 RVA %p - RVA %p\n",  pTable[i][0],pTable[i][1] - 1);
            memset(buffer,0,9);
            memcpy(buffer,pSectionTable[i].Name,8);
            if(*buffer)printf("节表名称<%s>\n",buffer);
            wantedIAT_sectionOffset = wantedIAT_RVA - pTable[i][0];
            indexForWantedIAT = i;
            break;
        }
    } 
    //以下到文件中去查找节中的IAT
    if(indexForWantedIAT > -1)
    {
        wantedIAT_fileOffset = wantedIAT_sectionOffset + pTable[indexForWantedIAT][2];
        printf("wanted IAT的文件偏移%p\n",wantedIAT_fileOffset);
        oldPos = ftell(fp);
        fseek(fp,wantedIAT_fileOffset,SEEK_SET);
        //IMAGE_THUNK_DATA thunk;
        fread(&thunk,1,sizeof thunk,fp);
        while(thunk.u1.Function)
        {
            wantedIAT_count += 1;
            fread(&thunk,1,sizeof thunk,fp);
        }
        printf("wanted IAT 有 %d 项（不包含零项）\n",wantedIAT_count);
        fseek(fp,oldPos,SEEK_SET);
    }
    //	以下计算NT可选头的SizeOfHeaders和SizeOfImage是否正确 
    {
        wantedHeadersSize = offsetSectionHeader + sectionCount * sizeof(IMAGE_SECTION_HEADER);
        printf("节表结束于%p.\n",wantedHeadersSize);
        wantedHeadersSize +=  (wantedHeadersSize % fileAlignment != 0)  *  (fileAlignment - wantedHeadersSize % fileAlignment);
        printf("SizeOfHeader 应为0x%X,实际为0x%X.\n",  wantedHeadersSize, ntHeader.OptionalHeader.SizeOfHeaders);
        if(wantedHeadersSize > ntHeader.OptionalHeader.SizeOfHeaders)
        {
            goto ReleaseResourcesAndWarn;
        }
        for( i = 0; i < sectionCount; ++i)
        {
            sectionImageSize += pTable[i][1] - pTable[i][0];
        }
        //将头部的大小按可选头的sectionAlignment域向上对齐后，
        //加入到总的镜像大小中
        //DWORD wantedImageSize;
        wantedImageSize =  sectionImageSize +  (wantedHeadersSize % pageAlignment != 0 ?  (1 + wantedHeadersSize / pageAlignment) *  pageAlignment  : wantedHeadersSize);
        printf("SizeOfImage 应为0x%X,实际为0x%X.\n",  wantedImageSize,  ntHeader.OptionalHeader.SizeOfImage);
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
        printf("不兼容的编译器，退出\n");
        free(pTable);
        free(pSectionTable);
        return -1;
    }
	
	printf("----------------sizeCode :%d\n",sizeCode);
    sizeFillForSection =  ((sizeCode % fileAlignment != 0) + sizeCode / fileAlignment) * fileAlignment;
    printf("扩展空间向上增长到%d字节\n",sizeFillForSection);    
    printf("下面开始着手构造新的可执行文件\n");
    {
    //增加一个节位于最后一个节的末尾
    //
    //我们会将代码加入到这个新节，
    //
    //新节会复制原有的导入描述符表到一个方便的位置，
    //以便我们增加描述符表的项目。
    //原有项目全部指向原来的RVA指针，
    //但新增一个针对kernel32.dll的项用于指向定制的IAT。
    //这个定制的IAT会为我们导入LoadLibraryA和GetProcAddress两个函数
    //
    //定制的IAT，以及自定义代码、
    //还有原导入描述符表的一个拷贝都位于新节中
    
    //要使用导入表的话我还没用想到别的方案。
    //暂时不想利用那些不需要导入表的方法
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
    printf("为头部扩充%u字节，为文件尾加入%u字节.\n", sizeFillForHeader,sizeFillForSection);
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

     //在这里增加节表
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
    
    //如果给文件头增加了长度，在下面填充无用数据
    while(ftell(fpFake) - ftell(fp) < sizeFillForHeader)
    {
        fputc(0xCC,fpFake);
    }
    //填充，直到到达原文件的最后一个可用节的末尾
    while(ftell(fpFake) <  lowestAvailableFileOffset + sizeFillForHeader)
    {
        fputc(fgetc(fp),fpFake);
    }
    printf("写到新文件的%p , 还差%u字节.\n",  ftell(fpFake),sizeFillForSection);
    fwrite(__invoke__start,1,sizeCode,fpFake);
    sizeFillForSection -= sizeCode;
	while (sizeFillForSection-- > 0){
		fputc(0x90, fpFake);
	}
    printf("写完所有填充，到文件偏移%p.\n",ftell(fpFake));
    
    //把原文件的末尾数据按原样写入。
    //有些程序依赖于在文件尾的一些附加数据，
    //而且是基于文件尾寻找偏移的
    while(ftell(fp) < sizeFillForHeader + sizeFillForSection + fileSize)
    {
        fputc(fgetc(fp),fpFake);
    }
    fclose(fp);
    printf("写完新文件，到文件偏移%p.\n",ftell(fpFake));
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