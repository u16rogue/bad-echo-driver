#include <cstdio>
#include <kita/kita.hpp>
#include <thread>
#include <Windows.h>

static auto on_pre_render(kita::events::on_pre_render * e) -> void
{
	std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

static auto on_render(kita::events::on_render * e) -> void
{
}

auto main() -> int
{

	FreeConsole();
	kita::kita_instance("bad-echo-driver-bridge", 300, 500)
		.callbacks(on_pre_render, on_render)
		.position()
		.show()
		.run()
	;	

	return 0;
}