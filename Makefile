#
# Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Copyright (c) 2018 Aalto University
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
SIGNING_KEY ?= ./src/enclave/enclave_private.pem

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

ifeq ($(SUPPLIED_KEY_DERIVATION), 1)
        SGX_COMMON_CFLAGS += -DSUPPLIED_KEY_DERIVATION
endif

######## Dependencies and output ########
Build_Dir := build
Generated_Dir := $(Build_Dir)/edger8red
$(shell   mkdir -p $(Build_Dir)/test/perf)
$(shell   mkdir -p $(Build_Dir)/enclave)
$(shell   mkdir -p $(Build_Dir)/net)
$(shell   mkdir -p $(Build_Dir)/logger)
$(shell   mkdir -p $(Build_Dir)/php)

Lib_Dir := ../safekeeper-libs
Lib_NrtTke := $(Lib_Dir)/lib_tke
Lib_NrtUke := $(Lib_Dir)/lib_uke
Lib_PhpCpp := $(Lib_Dir)/php_cpp
Lib_B64 := $(Lib_Dir)/libb64

NrtTke_Link := -L$(Lib_NrtTke) -lnrt_tke
NrtUke_Link := -L$(Lib_NrtUke) -lnrt_uke
PhpCpp_Link := -L$(Lib_PhpCpp) -lphpcpp
B64_Link := -L$(Lib_B64)/ -lb64 -Wl,-rpath=$(Lib_B64)


######## Test App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := test/perf/main.cpp sgx_errors.cpp safekeeper.cpp

App_Include_Paths := -Isrc -Isrc/logger -Isrc/net \
			-I$(SGX_SDK)/include \
			-I$(Generated_Dir) -I$(Lib_NrtTke) -I$(Lib_NrtUke) -I$(Lib_B64)/include

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11

App_Libs :=   -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) \
		$(NrtUke_Link) $(NrtTke_Link) $(B64_Link)

App_Link_Flags := $(SGX_COMMON_CFLAGS) $(App_Libs) -pthread

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:%.cpp=build/%.o)

App_Name := testing_app


######## Server Settings ########
Server_Cpp_Files := server.cpp logger/logger.cpp safekeeper.cpp net/socket.cpp sgx_errors.cpp

Server_Include_Paths := -Isrc -Isrc/logger -Isrc/net \
			-I$(SGX_SDK)/include \
			-I$(Generated_Dir) -I$(Lib_NrtTke) -I$(Lib_NrtUke) -I$(Lib_B64)/include

Server_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Server_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        Server_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        Server_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        Server_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Server_Cpp_Flags := $(Server_C_Flags) -std=c++11

Server_Libs :=   -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) \
		$(NrtUke_Link) $(NrtTke_Link) $(B64_Link)

Server_Link_Flags := $(SGX_COMMON_CFLAGS) $(Server_Libs) -pthread

ifneq ($(SGX_MODE), HW)
	Server_Link_Flags += -lsgx_uae_service_sim
else
	Server_Link_Flags += -lsgx_uae_service
endif

Server_Cpp_Objects := $(Server_Cpp_Files:%.cpp=build/%.o)

Server_Name := safekeeper

######## PHP Module Settings ########

Php_Cpp_Files := php/php_module.cpp safekeeper.cpp net/socket.cpp

Php_Include_Paths := -Isrc -Isrc/net \
			-I$(SGX_SDK)/include -I$(Lib_PhpCpp) -I$(Lib_PhpCpp)/include \
			-I$(Generated_Dir) -I$(Lib_NrtTke) -I$(Lib_NrtUke) -I$(Lib_B64)/include

Php_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Php_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        Php_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        Php_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        Php_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Php_Cpp_Flags := $(Php_C_Flags) -std=c++11

Php_Libs := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) \
		$(NrtUke_Link) $(NrtTke_Link) $(PhpCpp_Link) $(B64_Link)

Php_Link_Flags := -shared $(SGX_COMMON_CFLAGS) $(Php_Libs)

ifneq ($(SGX_MODE), HW)
	Php_Link_Flags += -lsgx_uae_service_sim
else
	Php_Link_Flags += -lsgx_uae_service
endif

Php_Cpp_Objects := $(Php_Cpp_Files:%.cpp=build/%.o)

Php_Module_Name := safekeeper


######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	UService_Library_Name := sgx_uae_service_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	UService_Library_Name := sgx_uae_service
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := enclave/enclave.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include \
			 -I$(SGX_SDK)/include/stlport  \
			 -I$(SGX_SDK)/include/tlibc    \
			 -Isrc -I$(Lib_NrtTke) \
			 -I$(Generated_Dir)

Enclave_C_Flags := $(SGX_COMMON_CFLAGS)                                  \
			-nostdinc -fvisibility=hidden -fpie -fstack-protector \
			$(Enclave_Include_Paths)

Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++03 -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags :=   $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx $(NrtTke_Link)        \
		-l$(Crypto_Library_Name) -l$(Service_Library_Name)        \
		-l$(UService_Library_Name) -Wl,--end-group                \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=src/enclave/enclave.lds 

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:%.cpp=build/%.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := src/enclave/enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: $(App_Name) $(Server_Name) build/enclave/$(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(Server_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(App_Name) $(Server_Name) build/enclave/$(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

php: build/php/$(Php_Module_Name).so

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name) 	
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif


######## SafeKeeper Object(s) ########

$(Build_Dir)/%.o: src/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"


######## PHP Module Object(s) ########

$(Build_Dir)/php/%.o: src/php/%.cpp
	@$(CXX) $(Php_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Build_Dir)/php/$(Php_Module_Name).so: $(Generated_Dir)/enclave_u.o $(Php_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Php_Link_Flags)
	@echo "LINK =>  $@"


######## Server Object(s) ########

$(Build_Dir)/logger/%.o: src/logger/%.cpp
	@$(CXX) $(Server_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Build_Dir)/net/%.o: src/net/%.cpp
	@$(CXX) $(Server_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Server_Name): $(Generated_Dir)/enclave_u.o $(Server_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Server_Link_Flags)
	@echo "LINK =>  $@"


######## Test and Enclave Objects ########

$(Generated_Dir)/enclave_u.c: $(SGX_EDGER8R) src/enclave/enclave.edl
	$(SGX_EDGER8R) --untrusted src/enclave/enclave.edl \
		--search-path src/enclave        \
		--search-path $(SGX_SDK)/include \
		--search-path $(Lib_NrtTke)      \
		--trusted-dir   $(Generated_Dir) \
		--untrusted-dir $(Generated_Dir)
	@echo "GEN  =>  $@"

$(Generated_Dir)/enclave_u.o: $(Generated_Dir)/enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Build_Dir)/test/perf/%.o: src/test/perf/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): $(Generated_Dir)/enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclave Objects ########

$(Generated_Dir)/enclave_t.c: $(SGX_EDGER8R) src/enclave/enclave.edl
	$(SGX_EDGER8R) --trusted src/enclave/enclave.edl \
		--search-path src/enclave        \
		--search-path $(SGX_SDK)/include \
		--search-path $(Lib_NrtTke)      \
		--trusted-dir   $(Generated_Dir) \
		--untrusted-dir $(Generated_Dir)
	@echo "GEN  =>  $@"

$(Generated_Dir)/enclave_t.o: $(Generated_Dir)/enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Build_Dir)/enclave/%.o: src/enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Build_Dir)/enclave/$(Enclave_Name): $(Generated_Dir)/enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Build_Dir)/enclave/$(Signed_Enclave_Name): $(Build_Dir)/enclave/$(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(SIGNING_KEY) \
		-enclave $(Build_Dir)/enclave/$(Enclave_Name) \
		-out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"


.PHONY: clean

clean:
	@rm -f $(App_Name) $(App_Cpp_Objects) $(Server_Cpp_Objects) \
		$(Build_Dir)/enclave/$(Enclave_Name) \
		$(Build_Dir)/enclave/$(Signed_Enclave_Name) \
		$(Generated_Dir)/enclave_u.* $(Enclave_Cpp_Objects) \
		$(Generated_Dir)/enclave_t.* $(Build_Dir)/verifier/libverifier.so \
		$(Verifier_Cpp_Objects)


Php_Extension_Dir := $(shell php-config --extension-dir)

install: build/php/safekeeper.so build/enclave/$(Signed_Enclave_Name)
	@cp build/php/safekeeper.so $(Php_Extension_Dir)
	@cp build/enclave/$(Signed_Enclave_Name) $(Php_Extension_Dir)/safekeeper.signed.so
	@echo "COPY =>  $< to $(Php_Extension_Dir)"

tags:
	@rm -f tags
	@ctags --extra=+qf -R -a .
	@ctags --extra=+qf -R -a ~/git/sgx/linux-sgx/sdk
	@ctags --extra=+qf -R -a ~/git/sgx/linux-sgx/common
