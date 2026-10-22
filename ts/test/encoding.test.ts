import { describe, expect, it } from "vite-plus/test";
import {
  b64uDecode,
  b64uEncode,
  bytesEqual,
  formatTime,
} from "../src/encoding.ts";
import { parseDuration, parseSince } from "../src/cli/util.ts";

describe("b64u", () => {
  it("round-trips without padding", () => {
    for (let n = 0; n < 40; n++) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37) & 0xff);
      const s = b64uEncode(bytes);
      expect(s).not.toMatch(/[=+/]/);
      expect(bytesEqual(b64uDecode(s) ?? new Uint8Array(), bytes)).toBe(true);
    }
  });

  it("rejects anything that isn't the canonical encoding", () => {
    expect(b64uDecode("AAAA=")).toBeNull(); // padding
    expect(b64uDecode("AA+/")).toBeNull(); // standard alphabet
    expect(b64uDecode("AB")).toBeNull(); // non-zero trailing bits
    expect(b64uDecode("A")).toBeNull(); // impossible length
    expect(b64uDecode("AA AA")).toBeNull(); // whitespace
    expect(b64uDecode("AA")).not.toBeNull();
  });
});

describe("formatTime", () => {
  it("drops milliseconds", () => {
    expect(formatTime(Date.parse("2026-10-22T12:34:56.789Z"))).toBe(
      "2026-10-22T12:34:56Z"
    );
  });
});

describe("CLI durations", () => {
  it("parses units and rejects junk", () => {
    expect(parseDuration("90s", "--x")).toBe(90_000);
    expect(parseDuration("24h", "--x")).toBe(86_400_000);
    expect(parseDuration("0", "--x")).toBe(0);
    expect(() => parseDuration("1.5h", "--x")).toThrow(/takes a duration/);
    expect(() => parseDuration("10", "--x")).toThrow(/takes a duration/);
  });

  it("reads --stale-since as a date or a duration ago", () => {
    const now = Date.parse("2026-10-22T12:00:00Z");
    expect(parseSince("36h", now)).toBe(now - 36 * 3_600_000);
    expect(parseSince("2026-03-01", now)).toBe(Date.parse("2026-03-01"));
    expect(() => parseSince("yesterday", now)).toThrow(/takes a date/);
  });
});
