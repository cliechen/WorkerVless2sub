/**
 * Utility functions extracted from _worker.js for testability.
 */

const ADDRESS_REGEX = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;

/**
 * Normalizes a string of addresses/tokens by replacing various delimiters
 * (tabs, quotes, newlines) with commas, deduplicating commas, trimming
 * leading/trailing commas, and splitting into an array.
 */
export async function organize(content) {
	var cleaned = content.replace(/[\t|"'\r\n]+/g, ',').replace(/,+/g, ',');

	if (cleaned.charAt(0) === ',') cleaned = cleaned.slice(1);
	if (cleaned.charAt(cleaned.length - 1) === ',') cleaned = cleaned.slice(0, cleaned.length - 1);

	const items = cleaned.split(',');
	return items;
}

/**
 * Validates whether a string is a valid IPv4 address.
 */
export function isValidIPv4(address) {
	const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
	return ipv4Regex.test(address);
}

/**
 * Selects a random proxy from socks5Data matching the given country code.
 * Falls back to "US" proxies, then to any random proxy.
 */
export function getRandomProxyByMatch(CC, socks5Data) {
	const lowerCaseMatch = CC.toLowerCase();

	let filteredProxies = socks5Data.filter(proxy => proxy.toLowerCase().endsWith(`#${lowerCaseMatch}`));

	if (filteredProxies.length === 0) {
		filteredProxies = socks5Data.filter(proxy => proxy.toLowerCase().endsWith(`#us`));
	}

	if (filteredProxies.length === 0) {
		return socks5Data[Math.floor(Math.random() * socks5Data.length)];
	}

	const randomProxy = filteredProxies[Math.floor(Math.random() * filteredProxies.length)];
	return randomProxy;
}

/**
 * Transforms Surge proxy list content by fixing WebSocket parameters.
 */
export function surge(content, url, path) {
	let lines;
	if (content.includes('\r\n')) {
		lines = content.split('\r\n');
	} else {
		lines = content.split('\n');
	}

	let output = "";
	for (let x of lines) {
		if (x.includes(atob(atob('UFNCMGNtOXFZVzRz')))) {
			const host = x.split("sni=")[1].split(",")[0];
			const oldParams = `skip-cert-verify=true, tfo=false, udp-relay=false`;
			const newParams = `skip-cert-verify=true, ws=true, ws-path=${path}, ws-headers=Host:"${host}", tfo=false, udp-relay=false`;
			output += x.replace(new RegExp(oldParams, 'g'), newParams).replace("[", "").replace("]", "") + '\n';
		} else {
			output += x + '\n';
		}
	}

	output = `#!MANAGED-CONFIG ${url.href} interval=86400 strict=false` + output.substring(output.indexOf('\n'));
	return output;
}

/**
 * Returns a static nginx welcome page HTML string.
 */
export async function nginx() {
	const text = `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>
	
	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>
	
	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`;
	return text;
}

/**
 * Replaces fake user ID and hostname with real values.
 */
export function revertFakeInfo(content, userID, hostName, fakeUserID, fakeHostName) {
	content = content.replace(new RegExp(fakeUserID, 'g'), userID).replace(new RegExp(fakeHostName, 'g'), hostName);
	return content;
}

/**
 * Replaces real user ID and hostname with fake values.
 */
export function generateFakeInfo(content, userID, hostName, fakeUserID, fakeHostName) {
	content = content.replace(new RegExp(userID, 'g'), fakeUserID).replace(new RegExp(hostName, 'g'), fakeHostName);
	return content;
}

/**
 * Encodes a UTF-8 string to Base64.
 */
export function utf8ToBase64(str) {
	return btoa(unescape(encodeURIComponent(str)));
}

/**
 * Computes a double MD5: MD5 the input, hex-encode, take chars [7..27),
 * MD5 again, hex-encode, and return lowercase.
 */
export async function MD5MD5(text) {
	const encoder = new TextEncoder();

	const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
	const firstPassArray = Array.from(new Uint8Array(firstPass));
	const firstHex = firstPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

	const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
	const secondPassArray = Array.from(new Uint8Array(secondPass));
	const secondHex = secondPassArray.map(b => b.toString(16).padStart(2, '0')).join('');

	return secondHex.toLowerCase();
}

/**
 * Parses CSV text into a 2D array. Handles Windows (\r\n), old Mac (\r),
 * and Unix (\n) line endings.
 */
export function parseCSV(text) {
	return text
		.replace(/\r\n/g, '\n')
		.replace(/\r/g, '\n')
		.split('\n')
		.filter(line => line.trim() !== '')
		.map(line => line.split(',').map(cell => cell.trim()));
}

/**
 * Moves items matching http(s) URLs from sourceArray into targetArray.
 * Returns the filtered sourceArray (without HTTP items).
 */
export function moveHttpUrls(sourceArray, targetArray) {
	if (!Array.isArray(sourceArray) || sourceArray.length === 0) return sourceArray || [];
	const httpRegex = /^https?:\/\//i;
	const httpUrls = sourceArray.filter(item => httpRegex.test(item));
	if (httpUrls.length > 0) {
		targetArray.push(...httpUrls);
		return sourceArray.filter(item => !httpRegex.test(item));
	}
	return sourceArray;
}

/**
 * Parses an address string using the standard address regex.
 * Returns { address, port, addressid } or null if no regex match
 * and the string needs fallback parsing.
 */
export function parseAddress(addressStr, defaultPort) {
	const match = addressStr.match(ADDRESS_REGEX);
	if (match) {
		return {
			address: match[1],
			port: match[2] || defaultPort,
			addressid: match[3] || match[1],
		};
	}
	return null;
}

/**
 * Fallback address parser for strings that don't match the regex.
 * Handles formats like "host:port#remark", "host:port", "host#remark".
 */
export function parseAddressFallback(addressStr, defaultPort) {
	let address = addressStr;
	let port = defaultPort;
	let addressid = addressStr;

	if (address.includes(':') && address.includes('#')) {
		const parts = address.split(':');
		address = parts[0];
		const subParts = parts[1].split('#');
		port = subParts[0];
		addressid = subParts[1];
	} else if (address.includes(':')) {
		const parts = address.split(':');
		address = parts[0];
		port = parts[1];
	} else if (address.includes('#')) {
		const parts = address.split('#');
		address = parts[0];
		addressid = parts[1];
	}

	if (addressid.includes(':')) {
		addressid = addressid.split(':')[0];
	}

	return { address, port, addressid };
}

export { ADDRESS_REGEX };
