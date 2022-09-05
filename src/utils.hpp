#pragma once

#define _UTILS_GLUE(m1, m2) m1 ## m2
#define UTILS_GLUE(m1, m2) _UTILS_GLUE(m1, m2)

namespace utils::details
{
	template <typename T>
	class __defer
	{
	public:
		__defer(T d)
			: d(d)
		{
		}
		~__defer()
		{
			d();
		}

	private:
		const T d;
	};
}

#define UTILS_DEFER \
	const utils::details::__defer UTILS_GLUE(__defer, __COUNTER__) = [&]() -> void

namespace utils
{
}