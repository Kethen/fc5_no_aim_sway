#include <windows.h>
#include <psapi.h>
#include <memoryapi.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <stdint.h>

// Patch obtained from https://fearlessrevolution.com/viewtopic.php?t=6317 by gir489

#define LOG_PATH "./fc5_no_aim_sway.log"

#define LOG(...) { \
	FILE *_log_file = fopen(LOG_PATH, "ab"); \
	if (_log_file != NULL){ \
		fprintf(_log_file, __VA_ARGS__); \
		fclose(_log_file); \
	} \
}

static void *find_pattern(const uint8_t *pattern, int size, uint64_t begin, uint64_t end){
	for(; begin + size < end; begin++){
		DWORD old_prot = 0;
		//VirtualProtect((void *)begin, size, PAGE_EXECUTE_READWRITE, &old_prot);
		if (memcmp((void *)begin, pattern, size) == 0){
			//VirtualProtect((void *)begin, size, old_prot, &old_prot);
			return (void *)begin;
		}
		//VirtualProtect((void *)begin, size, old_prot, &old_prot);
	}
	return NULL;
}

static void patch_memory(void *location, const uint8_t *patch, int size){
	DWORD old_prot = 0;
	VirtualProtect(location, size, PAGE_EXECUTE_READWRITE, &old_prot);
	memcpy(location, patch, size);
	VirtualProtect(location, size, old_prot, &old_prot);	
}

static void disable_aim_sway(HANDLE process, HMODULE module){
	MODULEINFO modinfo = {0};
	int get_module_info_result = GetModuleInformation(process, module, &modinfo, sizeof(modinfo));
	if (get_module_info_result == 0){
		LOG("%s: GetModuleInformation failed, 0x%x\n", __func__, GetLastError());
		return;
	}

	const uint8_t pattern[] = {0x80, 0xBB, 0xD4, 0x00, 0x00, 0x00, 0x00, 0xB1};
	const uint8_t patch[] = {0x80, 0xBB, 0xD4, 0x00, 0x00, 0x00, 0x01, 0xB1};
	void *patch_location = find_pattern(pattern, sizeof(pattern), (uint64_t)modinfo.lpBaseOfDll, (uint64_t)(modinfo.lpBaseOfDll + modinfo.SizeOfImage));
	if (patch_location == NULL){
		LOG("%s: patch location not found\n", __func__);
		return;
	}
	patch_memory(patch_location, patch, sizeof(patch));
	LOG("%s: patch applied at %p\n", __func__, patch_location);
}

static void find_and_patch_fc_m64(){
	HANDLE process = GetCurrentProcess();
	HMODULE modules[256];
	DWORD num_modules = 0;
	BOOL enumerate_result = EnumProcessModules(process, modules, sizeof(modules), &num_modules);
	if (!enumerate_result){
		LOG("%s: failed enumerating modules, 0x%x\n", __func__, GetLastError());
		return;
	}
	for (DWORD i = 0;i < num_modules;i++){
		char name_buf[1024] = {0};
		int name_len = GetModuleBaseNameA(process, modules[i], name_buf, sizeof(name_buf));
		if (name_len == 0){
			LOG("%s: GetModuleBaseNameA failed with %p, 0x%x\n", __func__, modules[i], GetLastError());
			continue;
		}
		for (int j = 0;j < name_len;j++){
			name_buf[j] = tolower(name_buf[j]);
		}
		if (strcmp(name_buf, "fc_m64.dll") == 0){
			disable_aim_sway(process, modules[i]);
			return;
		}
	}
	LOG("%s: fc_m64.dll not found in process\n", __func__);
}

__attribute__((constructor))
int init(){
	FILE *log_file = fopen(LOG_PATH, "wb");
	if (log_file != NULL){
		fclose(log_file);
	}
	find_and_patch_fc_m64();
}
