/**
 * Nera VPN™ - Robust IP & Geolocation Module (Upgraded)
 *
 * A robust, reliable module to fetch public IP and location data.
 * Designed to avoid rate limits during development and provide reliability in production.
 *
 * Strategy:
 * 1. Phase 1: Fetch IP from high-volume, plain-text providers (Rotation).
 * 2. Phase 2: Fetch Metadata (City/Country) from Geo providers (Rotation).
 * 3. Fallback: If Geo fails, return IP with "Unknown" placeholders.
 *
 * @module ipLocation
 */

// --- Configuration ---

const CACHE_DURATION_MS = 10 * 60 * 1000; // 10 minutes
const REQUEST_TIMEOUT_MS = 1500;

// Phase 1: Plain-text IP Providers (Reliable, unlimited)
const IP_PROVIDERS = [
    "https://api.ipify.org?format=text",
    "https://4.icanhazip.com", // Forced IPv4
    "https://ipinfo.io/ip",
    "https://checkip.amazonaws.com",
    "https://api.my-ip.io/ip",
    "https://wgetip.com",
    "https://ifconfig.me/ip",
];

// Phase 2: Geolocation Providers (Rate-limited, richer data)
const GEO_PROVIDERS = [
    {
        name: "ipapi",
        url: "https://ipapi.co/json/",
        normalize: (data) => ({
            city: data.city,
            country: data.country_name,
            countryCode: data.country_code,
        }),
    },
    {
        name: "ipinfo",
        url: "https://ipinfo.io/json",
        normalize: (data) => ({
            city: data.city,
            country: null, // ipinfo only implies country name from code often, or strictly code
            countryCode: data.country,
        }),
    },
    {
        name: "reallyfreegeoip",
        url: "https://reallyfreegeoip.com/json/",
        normalize: (data) => ({
            city: data.city,
            country: data.country_name,
            countryCode: data.country_code,
        }),
    },
];

// --- State ---

let cache = {
    data: null,
    timestamp: 0,
};

// --- Helpers ---

/**
 * Converts a 2-letter ISO country code to a flag emoji.
 * @param {string} countryCode - ISO 3166-1 alpha-2 code (e.g., "US", "FR")
 * @returns {string} Flag emoji or empty string if invalid
 */
function getFlagEmoji(countryCode) {
    if (!countryCode || countryCode.length !== 2) return "";
    const codePoints = countryCode
        .toUpperCase()
        .split("")
        .map((char) => 127462 + char.charCodeAt(0) - 65);
    return String.fromCodePoint(...codePoints);
}

/**
 * Fetches data from a URL with a strict timeout.
 * @param {string} url
 * @param {boolean} isJson - parse as JSON or Text
 * @returns {Promise<any>} Response data
 */
async function fetchWithTimeout(url, isJson = true) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(id);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return isJson ? await response.json() : await response.text();
    } catch (error) {
        clearTimeout(id);
        throw error;
    }
}

/**
 * Shuffles an array in place (Fisher-Yates).
 * @param {Array} array
 */
function shuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
}

// --- Main Export ---

/**
 * Retrieves the public IP and geolocation data.
 *
 * @param {boolean} [bypassCache=false] - Force fresh fetch
 * @returns {Promise<{
 *   ip: string,
 *   city: string,
 *   country: string,
 *   countryCode: string,
 *   flag: string
 * } | null>} Location object or null if IP detection fails completely.
 */
export async function getPublicIPAndLocation(bypassCache = false) {
    // 1. Check Cache
    const now = Date.now();
    if (!bypassCache && cache.data && now - cache.timestamp < CACHE_DURATION_MS) {
        return cache.data;
    }

    // 2. Phase 1: Get IP Address (Plain Text)
    let detectedIp = null;
    const ipProviders = [...IP_PROVIDERS];
    shuffleArray(ipProviders);

    for (const url of ipProviders) {
        try {
            const text = await fetchWithTimeout(url, false);
            const cleanIp = text.trim();
            // Basic length check + IPv4 check (no colons)
            if (cleanIp && cleanIp.length > 6 && !cleanIp.includes(":")) {
                detectedIp = cleanIp;
                break; // Success
            }
        } catch (e) {
            // Ignore, try next
        }
    }

    // If Phase 1 failed completely, we can't do anything reliable.
    if (!detectedIp) return null;

    // 3. Phase 2: Get Geolocation (Optional)
    let geoData = {
        city: "Unknown City",
        country: "Unknown Country",
        countryCode: "XX",
    };

    const geoProviders = [...GEO_PROVIDERS];
    shuffleArray(geoProviders);

    let geoSuccess = false;

    for (const provider of geoProviders) {
        try {
            const raw = await fetchWithTimeout(provider.url, true);
            const normalized = provider.normalize(raw);

            // Merge if we got valid data
            if (normalized.city || normalized.countryCode) {
                geoData = {
                    city: normalized.city || geoData.city,
                    country: normalized.country || normalized.countryCode || geoData.country,
                    countryCode: normalized.countryCode || geoData.countryCode,
                };
                geoSuccess = true;
                break; // Success
            }
        } catch (e) {
            // Ignore, try next
        }
    }

    // 4. Construct Final Result
    const finalResult = {
        ip: detectedIp,
        city: geoData.city,
        country: geoData.country,
        countryCode: geoData.countryCode,
        flag: getFlagEmoji(geoData.countryCode),
    };

    // 5. Update Cache
    cache = {
        data: finalResult,
        timestamp: now,
    };

    return finalResult;
}
