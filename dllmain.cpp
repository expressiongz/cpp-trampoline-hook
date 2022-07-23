#include <iostream>
#include <Windows.h>
#include <thread>

std::uint32_t tramp_hook( void* hook_addr, void* new_func, std::uint32_t instr_size ) 
{
	constexpr auto jmp_instr_size = 5;

	if ( instr_size < 5 ) {
		return 0;
	}

	DWORD vp_old_prot;
	VirtualProtect( hook_addr, instr_size, PAGE_EXECUTE_READWRITE, &vp_old_prot );
	std::memset( hook_addr, 0x90, instr_size );

	const auto rel_addr = ( reinterpret_cast< std::uint32_t>( new_func ) - reinterpret_cast< std::uint32_t >( hook_addr ) ) - jmp_instr_size;

	*( static_cast< std::uint8_t* >( hook_addr ) ) = 0xE9;
	*( reinterpret_cast < std::uint32_t* >( reinterpret_cast< std::uint32_t >( hook_addr ) + 1) ) = rel_addr;

	VirtualProtect( reinterpret_cast< void* >( hook_addr ), instr_size, vp_old_prot, nullptr );
	return reinterpret_cast< std::uint32_t >( hook_addr ) + jmp_instr_size;
}

std::uint32_t cont_execution_addr;

void _declspec( naked ) new_func() {
	__asm {
		inc [ eax ]
		lea eax, [ esp + 0x1C ]
		jmp cont_execution_addr
	}
}


void main()
{
	static const auto base_addr = reinterpret_cast< std::uint32_t >( GetModuleHandle( nullptr ) );
	auto* hook_addr = reinterpret_cast< void* >( base_addr + 0xC73EF );
	cont_execution_addr = tramp_hook( hook_addr, &new_func, 6 );
}

int __stdcall DllMain( HINSTANCE, const std::uint32_t reason_for_call, void* )
{
	if ( reason_for_call == DLL_PROCESS_ATTACH ) {
		std::thread( main ).detach();
	}
	return true;
}

