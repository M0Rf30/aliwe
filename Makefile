##
## Auto Generated makefile by CodeLite IDE
## any manual changes will be erased      
##
## Release
ProjectName            :=aliwe
ConfigurationName      :=Release
IntermediateDirectory  :=./Release
OutDir                 := $(IntermediateDirectory)
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
OutputFile             :=$(IntermediateDirectory)/$(ProjectName)
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


##
## User defined environment variables
##

Objects=$(IntermediateDirectory)/aliwe$(ObjectSuffix) 

##
## Main Build Targets 
##
all: $(OutputFile)

$(OutputFile): makeDirStep $(Objects)
	@$(MakeDirCommand) $(@D)
	$(LinkerName) $(OutputSwitch)$(OutputFile) $(Objects) $(LibPath) $(Libs) $(LinkOptions)

makeDirStep:
	@test -d ./Release || $(MakeDirCommand) ./Release

PreBuild:


##
## Objects
##
$(IntermediateDirectory)/aliwe$(ObjectSuffix): aliwe.c $(IntermediateDirectory)/aliwe$(DependSuffix)
	$(C_CompilerName) $(SourceSwitch) "aliwe.c" $(C_CmpOptions) $(ObjectSwitch)$(IntermediateDirectory)/aliwe$(ObjectSuffix) $(IncludePath)
$(IntermediateDirectory)/aliwe$(DependSuffix): aliwe.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) -MG -MP -MT$(IntermediateDirectory)/aliwe$(ObjectSuffix) -MF$(IntermediateDirectory)/aliwe$(DependSuffix) -MM "aliwe.c"

$(IntermediateDirectory)/aliwe$(PreprocessSuffix): aliwe.c
	@$(C_CompilerName) $(C_CmpOptions) $(IncludePath) $(PreprocessOnlySwitch) $(OutputSwitch) $(IntermediateDirectory)/aliwe$(PreprocessSuffix) "aliwe.c"


-include $(IntermediateDirectory)/*$(DependSuffix)
##
## Clean
##
clean:
	$(RM) $(IntermediateDirectory)/aliwe$(ObjectSuffix)
	$(RM) $(IntermediateDirectory)/aliwe$(DependSuffix)
	$(RM) $(IntermediateDirectory)/aliwe$(PreprocessSuffix)
	$(RM) $(OutputFile)


