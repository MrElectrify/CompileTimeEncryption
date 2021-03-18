#ifndef COMPILETIMEENCRYPTION_XORSTR_H_
#define COMPILETIMEENCRYPTION_XORSTR_H_

/// @file
/// Compile-time string XOR encryption
/// 3/18/21 11:48

// STL includes
#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

// Intel includes
#include <immintrin.h>

// yes, I hate macros. It's the neatest way
#ifdef _MSC_VER
#define FORCEINLINE __forceinline
#else
#define FORCEINLINE __attribute__((always_inline)) inline
#endif

#define XorStr(str) XorContext<str, __FILE__, __LINE__>().Decrypt().data()

#define XorStr_(str) XorContext<str, __FILE__, __LINE__>().Decrypt()

namespace CompileTimeEncryption
{
	namespace Detail
	{
		/// @brief A compile-time string
		template<unsigned N>
		struct FixedString {
			char buf[N + 1]{};
			constexpr FixedString(char const* s) {
				for (unsigned i = 0; i != N; ++i) buf[i] = s[i];
			}
			constexpr operator char const* () const { return buf; }
			constexpr size_t size() const { return N + 1; }
		};
		template<unsigned N> FixedString(char const (&)[N])->FixedString<N - 1>;

		/// @brief Calculates the splitmix hash of an integer
		/// @param x The value
		/// @return The hash
		constexpr uint64_t SplitMix64(uint64_t x)
		{
			x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
			x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
			x = x ^ (x >> 31);
			return x;
		}

		/// @brief Calculates the 64-bit FNV1 hash of a string
		/// @param ptr The pointer to the string
		/// @param hash The current hash
		/// @return The hash
		constexpr uint64_t FNV1(const char* ptr, uint64_t hash = 0xcbf29ce484222325) noexcept
		{
			return (*ptr != '\0') ? FNV1(ptr + 1, hash * 0x100000001b3 ^ *ptr) : hash;
		}

		/// @brief Calculates a pseudorandom number using the
		/// Linear Congruential Generator
		/// with values from MMIX by Donald Knuth
		/// @param lastVal The last random value
		/// @return The next random value
		constexpr uint64_t Random64(uint64_t lastVal) noexcept
		{
			constexpr uint64_t MULTIPLIER = 6364136223846793005;
			constexpr uint64_t INCREMENT = 1442695040888963407;
			return (MULTIPLIER * lastVal) + INCREMENT;
		}
		/// @brief Calculates a random char at an index
		/// @param seed The initial seed
		/// @param index The index of the char
		/// @return The random char
		constexpr char RandomChar(uint64_t seed, size_t index) noexcept
		{
			// since we extract a byte for each char, generate
			// the next random number as necessary
			for (size_t i = 0; i < (index / sizeof(seed)); ++i)
				seed = Random64(seed);
			// extract bytes from LSB to MSB
			return (seed >> (index % sizeof(seed) * 8)) & 0xff;
		}
		/// @brief Generates a unique seed per string and compile
		/// @tparam String The string to encrypt
		/// @tparam FileName The name of the file containing the string
		/// @tparam LineNumber The line number of the string
		/// @return The seed
		template<FixedString String, FixedString FileName, size_t LineNumber>
		constexpr uint64_t RandomSeed() noexcept
		{
			// there might be a better way to do this, but I am just gonna
			// throw the characters into a buffer to hash. it's either that,
			// or develop some expansion hash function
			return FNV1(String.buf) ^ FNV1(FileName) ^ FNV1(__DATE__ __TIME__) ^ SplitMix64(LineNumber);
		}

		/// @brief Aligns a value
		/// @param val The value to align
		/// @tparam Alignment The alignment to follow
		/// @return The aligned value
		template<size_t Alignment>
		constexpr size_t Align(size_t val)
		{
			if ((val % Alignment) != 0)
				val = ((val | Alignment - 1) + 1);
			return val;
		}

		/// @brief A compile-time for loop
		/// @tparam Start The start index
		/// @tparam End The end index
		/// @tparam Inc The increment value
		/// @tparam F The function type
		/// @param f The function
		template<auto Start, auto End, auto Inc, typename F>
		constexpr void constexpr_for(F&& f)
		{
			if constexpr (Start < End)
			{
				f.operator() < Start > ();
				constexpr_for<Start + Inc, End, Inc>(f);
			}
		}
	}

	/// @brief XorContext stores the key and encrypted buffer
	/// @tparam String The string to encrypt
	/// @tparam FileName The name of the file containing the string
	/// @tparam LineNumber The line number of the string
	template<Detail::FixedString String, Detail::FixedString FileName, size_t LineNumber>
	class XorContext
	{
	public:
		/// @brief Initializes the XorContext with the string
		constexpr XorContext() noexcept
		{
			constexpr auto seed = Detail::RandomSeed<String, FileName, LineNumber>();
			Detail::constexpr_for<0, String.size(), 1>([this, seed]<auto i>()
			{
				m_key[i] = std::integral_constant<char, Detail::RandomChar(seed, i)>::value;
				m_encBuf[i] = m_key[i] ^ std::integral_constant<char, String.buf[i]>::value;
			});
		}

		/// @brief Decrypts the stored string
		/// @return The stored string plus null padding
		FORCEINLINE std::array<char, Detail::Align<sizeof(__m128)>(std::integral_constant<size_t, String.size()>::value)> Decrypt() const noexcept
		{
			alignas(sizeof(__m128)) std::array<char, Detail::Align<sizeof(__m128)>(std::integral_constant<size_t, String.size()>::value)> result;
			// we use AVX because it is not only faster than simply looping with xor
			// but it will also prevent compile-time evaluation, which is the whole goal
			for (size_t i = 0; i < std::integral_constant<size_t, String.size()>::value; i += sizeof(__m128))
				_mm_store_ps(reinterpret_cast<float*>(result.data() + i),
					_mm_xor_ps(_mm_load_ps(reinterpret_cast<const float*>(m_key.data() + i)),
						_mm_load_ps(reinterpret_cast<const float*>(m_encBuf.data() + i))));
			return result;
		}
	private:
		// the key and encrypted value are both aligned to the size of __m128 because
		// intel's docs specify that AVX instructions require them to be aligned to
		// that size. the size is also aligned to the size of __m128 because it will 
		// be loaded into an AVX register, which is the size of __m128 in bytres
		alignas(sizeof(__m128)) std::array<char, Detail::Align<sizeof(__m128)>(std::integral_constant<size_t, String.size()>::value)> m_key;
		alignas(sizeof(__m128)) std::array<char, Detail::Align<sizeof(__m128)>(std::integral_constant<size_t, String.size()>::value)> m_encBuf;
	};
}

#endif