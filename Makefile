
## Release
ProjectName            :=aliwe
ConfigurationName      :=Release
WorkspacePath          := .
ProjectPath            := .
CurrentFileName        :=
CurrentFilePath        :=
CurrentFileFullPath    :=
User                   :=M0Rf30
Date                   :=06/01/2011
LinkerName             :=gcc
ArchiveTool            :=ar rcus
SharedObjectLinkerName :=gcc -shared -fPIC
ObjectSuffix           :=.o
DependSuffix           :=.o.d
PreprocessSuffix       :=.o.i
DebugSwitch            :=-g 
IncludeSwitch          :=-I
LibrarySwitch          :=-l
OutputSwitch           :=-o 
LibraryPathSwitch      :=-L
PreprocessorSwitch     :=-D
SourceSwitch           :=-c 
CompilerName           :=gcc
C_CompilerName         :=gcc
OutputFile             :=$(ProjectName)
Preprocessors          :=
ObjectSwitch           :=-o 
ArchiveOutputSwitch    := 
PreprocessOnlySwitch   :=-E 
MakeDirCommand         :=mkdir -p
CmpOptions             :=  $(Preprocessors)
C_CmpOptions           :=  $(Preprocessors)
LinkOptions            :=  -O2
IncludePath            :=  "$(IncludeSwitch)/usr/include" "$(IncludeSwitch)/usr/include" 
RcIncludePath          :=
Libs                   :=  /usr/lib/libcrypto.so
LibPath                := "$(LibraryPathSwitch)/usr/lib" 
PREFIX		       := usr
DESTDIR		       :=
BINDIR		       :=$(DESTDIR)/$(PREFIX)/bin
DATA                   :=$(DESTDIR)/$(PREFIX)/share/aliwe
OTHER		       := models \
			  COPYING \
			  README \
			  AUTHORS \
			  INSTALL
##
## User defined environment variables
##

Objects=aliwe$(ObjectSuffix) 

##
## Main Build Targets 
##
all: $(OutputFile)

$(OutputFile): makeDirStep $(Objects)
	@$(MakeDirCommand) $(@D)
	$(LinkerName) $(OutputSwitch)$(OutputFile) $(Objects) $(LibPath) $(Libs) $(LinkOptions)

makeDirStep:
	@test -d . || $(MakeDirCommand) .

PreBuild:


##
## Objects
##
aliwe$(ObjectSuffix): aliwe.c aliwe$(DependSuffix)
	$(C_CompilerName) $(SourceSwitch) "aliwe.c" $(C_CmpOptions) $(ObjectSwitch)aliwe$(ObjectSuffix) $(IncludePath)
aliwe$(DependSuffix): aliwe.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) -MG -MP -MTaliwe$(ObjectSuffix) -MFaliwe$(DependSuffix) -MM "aliwe.c"

aliwe$(PreprocessSuffix): aliwe.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) aliwe$(PreprocessSuffix) "aliwe.c"


-include *$(DependSuffix)
##
## Clean
##
clean:
	$(RM) aliwe$(ObjectSuffix)
	$(RM) aliwe$(DependSuffix)
	$(RM) aliwe$(PreprocessSuffix)
	$(RM) $(OutputFile)

install:
	install -c -Dm777 $(OutputFile) $(BINDIR)/$(OutputFile)
	mkdir -p $(DATA)
	install -c -m777 $(OTHER)  $(DATA)