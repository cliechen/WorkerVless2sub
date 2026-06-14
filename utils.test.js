import { describe, it, expect, vi } from 'vitest';
import {
	organize,
	isValidIPv4,
	getRandomProxyByMatch,
	surge,
	nginx,
	revertFakeInfo,
	generateFakeInfo,
	utf8ToBase64,
	parseCSV,
	moveHttpUrls,
	parseAddress,
	parseAddressFallback,
	ADDRESS_REGEX,
} from './utils.js';

// ─── organize (整理) ─────────────────────────────────────────────────────────

describe('organize', () => {
	it('splits comma-separated values', async () => {
		expect(await organize('a,b,c')).toEqual(['a', 'b', 'c']);
	});

	it('splits tab-separated values', async () => {
		expect(await organize('a\tb\tc')).toEqual(['a', 'b', 'c']);
	});

	it('splits newline-separated values', async () => {
		expect(await organize('a\nb\nc')).toEqual(['a', 'b', 'c']);
	});

	it('splits \\r\\n-separated values', async () => {
		expect(await organize('a\r\nb\r\nc')).toEqual(['a', 'b', 'c']);
	});

	it('handles pipe-separated values', async () => {
		expect(await organize('a|b|c')).toEqual(['a', 'b', 'c']);
	});

	it('handles double-quote-separated values', async () => {
		expect(await organize('a"b"c')).toEqual(['a', 'b', 'c']);
	});

	it('handles single-quote-separated values', async () => {
		expect(await organize("a'b'c")).toEqual(['a', 'b', 'c']);
	});

	it('collapses consecutive commas into one', async () => {
		expect(await organize('a,,,,b')).toEqual(['a', 'b']);
	});

	it('trims leading comma', async () => {
		expect(await organize(',a,b')).toEqual(['a', 'b']);
	});

	it('trims trailing comma', async () => {
		expect(await organize('a,b,')).toEqual(['a', 'b']);
	});

	it('trims both leading and trailing commas', async () => {
		expect(await organize(',a,b,')).toEqual(['a', 'b']);
	});

	it('handles mixed delimiters', async () => {
		expect(await organize('a\tb\nc"d\'e')).toEqual(['a', 'b', 'c', 'd', 'e']);
	});

	it('returns single element for a single value', async () => {
		expect(await organize('hello')).toEqual(['hello']);
	});

	it('handles empty string (returns one empty element)', async () => {
		expect(await organize('')).toEqual(['']);
	});
});

// ─── isValidIPv4 ─────────────────────────────────────────────────────────────

describe('isValidIPv4', () => {
	it('accepts 0.0.0.0', () => {
		expect(isValidIPv4('0.0.0.0')).toBe(true);
	});

	it('accepts 255.255.255.255', () => {
		expect(isValidIPv4('255.255.255.255')).toBe(true);
	});

	it('accepts typical private IP', () => {
		expect(isValidIPv4('192.168.1.1')).toBe(true);
	});

	it('accepts loopback', () => {
		expect(isValidIPv4('127.0.0.1')).toBe(true);
	});

	it('rejects octet > 255', () => {
		expect(isValidIPv4('256.0.0.1')).toBe(false);
	});

	it('rejects too few octets', () => {
		expect(isValidIPv4('192.168.1')).toBe(false);
	});

	it('rejects too many octets', () => {
		expect(isValidIPv4('192.168.1.1.1')).toBe(false);
	});

	it('rejects empty string', () => {
		expect(isValidIPv4('')).toBe(false);
	});

	it('rejects alphabetic', () => {
		expect(isValidIPv4('abc.def.ghi.jkl')).toBe(false);
	});

	it('rejects IPv6', () => {
		expect(isValidIPv4('::1')).toBe(false);
	});

	it('rejects hostname', () => {
		expect(isValidIPv4('example.com')).toBe(false);
	});

	it('rejects negative numbers', () => {
		expect(isValidIPv4('-1.0.0.0')).toBe(false);
	});

	it('accepts single-digit octets', () => {
		expect(isValidIPv4('1.2.3.4')).toBe(true);
	});

	it('accepts two-digit octets', () => {
		expect(isValidIPv4('10.20.30.40')).toBe(true);
	});
});

// ─── getRandomProxyByMatch ───────────────────────────────────────────────────

describe('getRandomProxyByMatch', () => {
	const socks5Data = [
		'1.2.3.4:1080#us',
		'5.6.7.8:1080#us',
		'9.10.11.12:1080#jp',
		'13.14.15.16:1080#de',
	];

	it('returns a proxy matching the given country code', () => {
		const result = getRandomProxyByMatch('JP', socks5Data);
		expect(result).toBe('9.10.11.12:1080#jp');
	});

	it('is case-insensitive for country code', () => {
		const result = getRandomProxyByMatch('De', socks5Data);
		expect(result).toBe('13.14.15.16:1080#de');
	});

	it('falls back to US when no match', () => {
		const result = getRandomProxyByMatch('FR', socks5Data);
		expect(['1.2.3.4:1080#us', '5.6.7.8:1080#us']).toContain(result);
	});

	it('falls back to random when no US either', () => {
		const noUSData = ['9.10.11.12:1080#jp', '13.14.15.16:1080#de'];
		const result = getRandomProxyByMatch('FR', noUSData);
		expect(noUSData).toContain(result);
	});

	it('returns the only proxy when single match', () => {
		const single = ['1.1.1.1:1080#uk'];
		expect(getRandomProxyByMatch('UK', single)).toBe('1.1.1.1:1080#uk');
	});
});

// ─── surge ───────────────────────────────────────────────────────────────────

describe('surge', () => {
	const fakeUrl = new URL('https://example.com/sub');

	it('prepends MANAGED-CONFIG header', () => {
		const result = surge('line1\nline2', fakeUrl, '/ws');
		expect(result.startsWith('#!MANAGED-CONFIG https://example.com/sub interval=86400 strict=false')).toBe(true);
	});

	it('preserves non-trojan lines (after the first line which becomes MANAGED-CONFIG)', () => {
		const result = surge('first line\nanother line\nthird line', fakeUrl, '/ws');
		// First line is replaced by MANAGED-CONFIG header
		expect(result).not.toContain('first line');
		expect(result).toContain('another line');
		expect(result).toContain('third line');
	});

	it('handles CRLF line endings', () => {
		const result = surge('header line\r\nline2\r\nline3', fakeUrl, '/ws');
		expect(result).toContain('line2');
		expect(result).toContain('line3');
	});

	it('handles empty content', () => {
		const result = surge('', fakeUrl, '/ws');
		expect(result).toContain('#!MANAGED-CONFIG');
	});
});

// ─── nginx ───────────────────────────────────────────────────────────────────

describe('nginx', () => {
	it('returns HTML with DOCTYPE', async () => {
		const html = await nginx();
		expect(html).toContain('<!DOCTYPE html>');
	});

	it('contains nginx title', async () => {
		const html = await nginx();
		expect(html).toContain('<title>Welcome to nginx!</title>');
	});

	it('contains nginx heading', async () => {
		const html = await nginx();
		expect(html).toContain('<h1>Welcome to nginx!</h1>');
	});

	it('contains links to nginx.org', async () => {
		const html = await nginx();
		expect(html).toContain('http://nginx.org/');
		expect(html).toContain('http://nginx.com/');
	});
});

// ─── revertFakeInfo / generateFakeInfo ───────────────────────────────────────

describe('revertFakeInfo', () => {
	const fakeUID = 'fake-uuid-1234';
	const fakeHost = 'fake.host.xyz';
	const realUID = 'real-uuid-5678';
	const realHost = 'real.host.com';

	it('replaces fake ID and hostname with real ones', () => {
		const content = `config uuid=${fakeUID} host=${fakeHost}`;
		const result = revertFakeInfo(content, realUID, realHost, fakeUID, fakeHost);
		expect(result).toBe(`config uuid=${realUID} host=${realHost}`);
	});

	it('replaces multiple occurrences', () => {
		const content = `${fakeUID} and ${fakeUID}`;
		const result = revertFakeInfo(content, realUID, realHost, fakeUID, fakeHost);
		expect(result).toBe(`${realUID} and ${realUID}`);
	});

	it('returns unchanged content when no matches', () => {
		const content = 'no fake info here';
		const result = revertFakeInfo(content, realUID, realHost, fakeUID, fakeHost);
		expect(result).toBe('no fake info here');
	});
});

describe('generateFakeInfo', () => {
	const fakeUID = 'fake-uuid-1234';
	const fakeHost = 'fake.host.xyz';
	const realUID = 'real-uuid-5678';
	const realHost = 'real.host.com';

	it('replaces real ID and hostname with fake ones', () => {
		const content = `config uuid=${realUID} host=${realHost}`;
		const result = generateFakeInfo(content, realUID, realHost, fakeUID, fakeHost);
		expect(result).toBe(`config uuid=${fakeUID} host=${fakeHost}`);
	});

	it('replaces multiple occurrences', () => {
		const content = `${realHost} and ${realHost}`;
		const result = generateFakeInfo(content, realUID, realHost, fakeUID, fakeHost);
		expect(result).toBe(`${fakeHost} and ${fakeHost}`);
	});

	it('round-trips with revertFakeInfo', () => {
		const original = `uuid=${realUID} host=${realHost}`;
		const faked = generateFakeInfo(original, realUID, realHost, fakeUID, fakeHost);
		const reverted = revertFakeInfo(faked, realUID, realHost, fakeUID, fakeHost);
		expect(reverted).toBe(original);
	});
});

// ─── utf8ToBase64 ────────────────────────────────────────────────────────────

describe('utf8ToBase64', () => {
	it('encodes ASCII string', () => {
		expect(utf8ToBase64('hello')).toBe(btoa('hello'));
	});

	it('encodes empty string', () => {
		expect(utf8ToBase64('')).toBe('');
	});

	it('encodes string with special chars', () => {
		const encoded = utf8ToBase64('a+b=c');
		expect(atob(encoded)).toBe('a+b=c');
	});

	it('encodes unicode (Chinese characters)', () => {
		const encoded = utf8ToBase64('你好');
		expect(encoded).toBeTruthy();
		expect(typeof encoded).toBe('string');
		// Verify round-trip
		const decoded = decodeURIComponent(escape(atob(encoded)));
		expect(decoded).toBe('你好');
	});

	it('encodes unicode (emoji)', () => {
		const encoded = utf8ToBase64('🚀');
		const decoded = decodeURIComponent(escape(atob(encoded)));
		expect(decoded).toBe('🚀');
	});
});

// ─── parseCSV ────────────────────────────────────────────────────────────────

describe('parseCSV', () => {
	it('parses simple CSV', () => {
		const result = parseCSV('a,b,c\n1,2,3');
		expect(result).toEqual([
			['a', 'b', 'c'],
			['1', '2', '3'],
		]);
	});

	it('handles Windows \\r\\n line endings', () => {
		const result = parseCSV('a,b\r\n1,2');
		expect(result).toEqual([
			['a', 'b'],
			['1', '2'],
		]);
	});

	it('handles old Mac \\r line endings', () => {
		const result = parseCSV('a,b\r1,2');
		expect(result).toEqual([
			['a', 'b'],
			['1', '2'],
		]);
	});

	it('trims whitespace from cells', () => {
		const result = parseCSV('  a , b \n 1 , 2 ');
		expect(result).toEqual([
			['a', 'b'],
			['1', '2'],
		]);
	});

	it('filters out empty lines', () => {
		const result = parseCSV('a,b\n\n1,2\n\n');
		expect(result).toEqual([
			['a', 'b'],
			['1', '2'],
		]);
	});

	it('handles single row', () => {
		const result = parseCSV('a,b,c');
		expect(result).toEqual([['a', 'b', 'c']]);
	});

	it('handles single cell', () => {
		const result = parseCSV('hello');
		expect(result).toEqual([['hello']]);
	});

	it('handles empty string', () => {
		const result = parseCSV('');
		expect(result).toEqual([]);
	});

	it('preserves numeric-looking strings', () => {
		const result = parseCSV('IP,Port,TLS\n1.2.3.4,443,TRUE');
		expect(result).toEqual([
			['IP', 'Port', 'TLS'],
			['1.2.3.4', '443', 'TRUE'],
		]);
	});
});

// ─── moveHttpUrls ────────────────────────────────────────────────────────────

describe('moveHttpUrls', () => {
	it('moves http URLs to target array', () => {
		const source = ['1.2.3.4', 'http://example.com/api', '5.6.7.8'];
		const target = [];
		const result = moveHttpUrls(source, target);
		expect(result).toEqual(['1.2.3.4', '5.6.7.8']);
		expect(target).toEqual(['http://example.com/api']);
	});

	it('moves https URLs to target array', () => {
		const source = ['1.2.3.4', 'https://example.com/api'];
		const target = [];
		const result = moveHttpUrls(source, target);
		expect(result).toEqual(['1.2.3.4']);
		expect(target).toEqual(['https://example.com/api']);
	});

	it('is case-insensitive for HTTP prefix', () => {
		const source = ['HTTP://EXAMPLE.COM'];
		const target = [];
		const result = moveHttpUrls(source, target);
		expect(result).toEqual([]);
		expect(target).toEqual(['HTTP://EXAMPLE.COM']);
	});

	it('returns source unchanged when no HTTP URLs', () => {
		const source = ['1.2.3.4', '5.6.7.8'];
		const target = [];
		const result = moveHttpUrls(source, target);
		expect(result).toEqual(['1.2.3.4', '5.6.7.8']);
		expect(target).toEqual([]);
	});

	it('returns empty array for empty source', () => {
		const target = [];
		const result = moveHttpUrls([], target);
		expect(result).toEqual([]);
		expect(target).toEqual([]);
	});

	it('returns empty array for null source', () => {
		const target = [];
		const result = moveHttpUrls(null, target);
		expect(result).toEqual([]);
	});

	it('returns empty array for undefined source', () => {
		const target = [];
		const result = moveHttpUrls(undefined, target);
		expect(result).toEqual([]);
	});

	it('appends to existing target items', () => {
		const source = ['http://new.com'];
		const target = ['http://existing.com'];
		const result = moveHttpUrls(source, target);
		expect(result).toEqual([]);
		expect(target).toEqual(['http://existing.com', 'http://new.com']);
	});

	it('handles multiple HTTP URLs', () => {
		const source = ['http://a.com', 'plain', 'https://b.com'];
		const target = [];
		const result = moveHttpUrls(source, target);
		expect(result).toEqual(['plain']);
		expect(target).toEqual(['http://a.com', 'https://b.com']);
	});
});

// ─── parseAddress (regex-based) ──────────────────────────────────────────────

describe('parseAddress', () => {
	it('parses IP:port#remark', () => {
		const result = parseAddress('1.2.3.4:443#myserver', '-1');
		expect(result).toEqual({
			address: '1.2.3.4',
			port: '443',
			addressid: 'myserver',
		});
	});

	it('parses IP:port without remark', () => {
		const result = parseAddress('1.2.3.4:443', '-1');
		expect(result).toEqual({
			address: '1.2.3.4',
			port: '443',
			addressid: '1.2.3.4',
		});
	});

	it('parses IP without port (uses default)', () => {
		const result = parseAddress('1.2.3.4', '-1');
		expect(result).toEqual({
			address: '1.2.3.4',
			port: '-1',
			addressid: '1.2.3.4',
		});
	});

	it('parses IPv6 bracket notation', () => {
		const result = parseAddress('[::1]:443#v6', '-1');
		expect(result).toEqual({
			address: '[::1]',
			port: '443',
			addressid: 'v6',
		});
	});

	it('returns null for hostname (no regex match)', () => {
		const result = parseAddress('example.com:443#remark', '-1');
		expect(result).toBeNull();
	});

	it('returns null for plain hostname', () => {
		const result = parseAddress('example.com', '-1');
		expect(result).toBeNull();
	});
});

// ─── parseAddressFallback ────────────────────────────────────────────────────

describe('parseAddressFallback', () => {
	it('parses host:port#remark', () => {
		const result = parseAddressFallback('example.com:443#mynode', '-1');
		expect(result).toEqual({
			address: 'example.com',
			port: '443',
			addressid: 'mynode',
		});
	});

	it('parses host:port without remark (addressid colon is stripped)', () => {
		const result = parseAddressFallback('example.com:443', '-1');
		expect(result).toEqual({
			address: 'example.com',
			port: '443',
			addressid: 'example.com',
		});
	});

	it('parses host#remark without port', () => {
		const result = parseAddressFallback('example.com#mynode', '-1');
		expect(result).toEqual({
			address: 'example.com',
			port: '-1',
			addressid: 'mynode',
		});
	});

	it('returns full string as address and addressid when no separators', () => {
		const result = parseAddressFallback('example.com', '-1');
		expect(result).toEqual({
			address: 'example.com',
			port: '-1',
			addressid: 'example.com',
		});
	});

	it('strips port from addressid if it contains colon', () => {
		const result = parseAddressFallback('example.com:443#node:extra', '-1');
		expect(result.addressid).toBe('node');
	});
});

// ─── ADDRESS_REGEX ───────────────────────────────────────────────────────────

describe('ADDRESS_REGEX', () => {
	it('matches standard IPv4:port#remark', () => {
		const m = '192.168.1.1:443#test'.match(ADDRESS_REGEX);
		expect(m).not.toBeNull();
		expect(m[1]).toBe('192.168.1.1');
		expect(m[2]).toBe('443');
		expect(m[3]).toBe('test');
	});

	it('matches IPv4 only', () => {
		const m = '10.0.0.1'.match(ADDRESS_REGEX);
		expect(m).not.toBeNull();
		expect(m[1]).toBe('10.0.0.1');
		expect(m[2]).toBeUndefined();
		expect(m[3]).toBeUndefined();
	});

	it('matches bracketed IPv6:port#remark', () => {
		const m = '[2001:db8::1]:8443#v6node'.match(ADDRESS_REGEX);
		expect(m).not.toBeNull();
		expect(m[1]).toBe('[2001:db8::1]');
		expect(m[2]).toBe('8443');
		expect(m[3]).toBe('v6node');
	});

	it('does not match hostname', () => {
		const m = 'example.com'.match(ADDRESS_REGEX);
		expect(m).toBeNull();
	});
});
