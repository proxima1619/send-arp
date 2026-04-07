#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>

// ----------------------------------------------------------------------------
// Mac
// ----------------------------------------------------------------------------
struct Mac final {
	static constexpr int Size = 6;

	// constructor
	Mac() {}
	Mac(const Mac& r) { memcpy(this->mac_, r.mac_, Size); }
	Mac(const uint8_t* r) { memcpy(this->mac_, r, Size); }
	Mac(const std::string& r);

	// assign operator
	Mac& operator = (const Mac& r) { memcpy(this->mac_, r.mac_, Size); return *this; }

	// casting operator
	explicit operator uint8_t*() const { return const_cast<uint8_t*>(mac_); }
	explicit operator std::string() const;

	// comparison operator
	bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, Size) == 0; }
	bool operator != (const Mac& r) const { return memcmp(mac_, r.mac_, Size) != 0; }
	bool operator < (const Mac& r) const { return memcmp(mac_, r.mac_, Size) < 0; }
	bool operator > (const Mac& r) const { return memcmp(mac_, r.mac_, Size) > 0; }
	bool operator <= (const Mac& r) const { return memcmp(mac_, r.mac_, Size) <= 0; }
	bool operator >= (const Mac& r) const { return memcmp(mac_, r.mac_, Size) >= 0; }
	bool operator == (const uint8_t* r) const { return memcmp(mac_, r, Size) == 0; }

	void clear() {
		*this = nullMac();
	}

	bool isNull() const {
		return *this == nullMac();
	}

	bool isBroadcast() const { // FF:FF:FF:FF:FF:FF
		return *this == broadcastMac();
	}

	bool isMulticast() const { // 01:00:5E:0*
		return mac_[0] == 0x01 && mac_[1] == 0x00 && mac_[2] == 0x5E && (mac_[3] & 0x80) == 0x00;
	}

	static Mac randomMac();
	static Mac& nullMac();
	static Mac& broadcastMac();

protected:
	uint8_t mac_[Size];
};

namespace std {
	template<>
	struct hash<Mac> {
		size_t operator() (const Mac& r) const {
			const auto* bytes = reinterpret_cast<const uint8_t*>(&r);
			size_t hash = 1469598103934665603ull;
			for (int i = 0; i < Mac::Size; i++) {
				hash ^= bytes[i];
				hash *= 1099511628211ull;
			}
			return hash;
		}
	};
}
