using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace FlagInjector;

static class W32
{
    public const uint ACCESS = 0x0438;
    public const uint SNAP = 0x18;
    public const uint ALIVE = 259;

    [DllImport("kernel32", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint a, bool b, int pid);
    [DllImport("kernel32", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int n, out int read);
    [DllImport("kernel32", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int n, out int wrote);
    [DllImport("kernel32", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint f, uint pid);
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool Module32FirstW(IntPtr snap, ref MODENTRY me);
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool Module32NextW(IntPtr snap, ref MODENTRY me);
    [DllImport("kernel32")]
    public static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("user32", CharSet = CharSet.Unicode)]
    public static extern IntPtr SendMessage(IntPtr hw, uint msg, IntPtr wp, string lp);
    [DllImport("dwmapi")]
    public static extern int DwmSetWindowAttribute(IntPtr hw, int attr, ref int val, int sz);
    [DllImport("uxtheme", CharSet = CharSet.Unicode)]
    public static extern int SetWindowTheme(IntPtr hw, string sub, string? id);
    [DllImport("user32")]
    public static extern bool DestroyIcon(IntPtr h);
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct MODENTRY
{
    public uint dwSize; public uint modID; public uint procID; public uint glblCnt; public uint procCnt;
    public IntPtr modBaseAddr; public uint modBaseSize; public IntPtr hModule;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
}

sealed class AppLog : IDisposable
{
    readonly string _path;
    readonly object _lk = new();
    StreamWriter? _w;

    public AppLog(string dir)
    {
        _path = Path.Combine(dir, "log.txt");
        try
        {
            _w = new StreamWriter(_path, true, Encoding.UTF8) { AutoFlush = true };
            if (new FileInfo(_path).Length > 2 * 1024 * 1024)
            {
                _w.Dispose();
                File.Delete(_path);
                _w = new StreamWriter(_path, false, Encoding.UTF8) { AutoFlush = true };
            }
        }
        catch { _w = null; }
    }

    public void Info(string msg) => Write("INF", msg);
    public void Warn(string msg) => Write("WRN", msg);
    public void Error(string msg) => Write("ERR", msg);

    void Write(string lvl, string msg)
    {
        lock (_lk)
        {
            try { _w?.WriteLine($"{DateTime.Now:HH:mm:ss.fff} [{lvl}] {msg}"); } catch { }
        }
    }

    public void Dispose()
    {
        lock (_lk) { _w?.Dispose(); _w = null; }
    }
}

sealed class AppSettings
{
    public int X { get; set; } = -1;
    public int Y { get; set; } = -1;
    public int W { get; set; } = 780;
    public int H { get; set; } = 740;
    public int Split { get; set; } = -1;
    public bool AutoApply { get; set; } = true;
    public bool Watchdog { get; set; } = true;
    public bool AlwaysOnTop { get; set; }
    public int SchemaVer { get; set; } = 1;

    static readonly JsonSerializerOptions _jopt = new() { WriteIndented = true };

    public static AppSettings Load(string path)
    {
        try
        {
            if (!File.Exists(path)) return new();
            return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path, Encoding.UTF8)) ?? new();
        }
        catch { return new(); }
    }

    public void Save(string path)
    {
        try
        {
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(this, _jopt), new UTF8Encoding(false));
            if (File.Exists(path)) try { File.Copy(path, path + ".bak", true); } catch { }
            File.Move(tmp, path, true);
        }
        catch { }
    }
}

sealed class FlagDto
{
    [JsonPropertyName("n")] public string Name { get; set; } = "";
    [JsonPropertyName("v")] public string Value { get; set; } = "";
    [JsonPropertyName("t")] public string Type { get; set; } = "String";
    [JsonPropertyName("e")] public bool Enabled { get; set; } = true;
}

sealed class NameResolver
{
    readonly Dictionary<string, string> _exact = new();
    readonly Dictionary<string, string> _ci = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, string> _stripped = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, string> _norm = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, string> _strippedNorm = new(StringComparer.OrdinalIgnoreCase);

    public void Add(string canonical)
    {
        if (_exact.ContainsKey(canonical)) return;
        _exact[canonical] = canonical;
        _ci[canonical] = canonical;
        string s = FlagPrefix.Strip(canonical);
        if (!_stripped.ContainsKey(s)) _stripped[s] = canonical;
        string n = canonical.Replace("_", "");
        if (!_norm.ContainsKey(n)) _norm[n] = canonical;
        string sn = s.Replace("_", "");
        if (!_strippedNorm.ContainsKey(sn)) _strippedNorm[sn] = canonical;
    }

    public string? Resolve(string name)
    {
        if (_exact.ContainsKey(name)) return name;
        if (_ci.TryGetValue(name, out var a)) return a;
        string s = FlagPrefix.Strip(name);
        if (s != name)
        {
            if (_ci.TryGetValue(s, out var b)) return b;
            if (_stripped.TryGetValue(s, out var c)) return c;
            if (_strippedNorm.TryGetValue(s.Replace("_", ""), out var d)) return d;
        }
        if (_stripped.TryGetValue(name, out var e)) return e;
        if (_norm.TryGetValue(name.Replace("_", ""), out var f)) return f;
        if (_strippedNorm.TryGetValue(name.Replace("_", ""), out var g)) return g;
        return null;
    }

    public void Clear()
    {
        _exact.Clear(); _ci.Clear(); _stripped.Clear(); _norm.Clear(); _strippedNorm.Clear();
    }
}

sealed class MemEngine : IDisposable
{
    IntPtr _h, _base;
    int _pid;
    uint _modSize;
    readonly object _lk = new();

    public bool On => _h != IntPtr.Zero && _base != IntPtr.Zero;
    public int Pid { get { lock (_lk) return _pid; } }
    public long Base { get { lock (_lk) return _base.ToInt64(); } }
    public uint ModSize { get { lock (_lk) return _modSize; } }
    public event Action<string>? Log;

    public bool Attach(int pid, string mod = "RobloxPlayerBeta.exe", CancellationToken ct = default)
    {
        lock (_lk)
        {
            Detach();
            var h = W32.OpenProcess(W32.ACCESS, false, pid);
            if (h == IntPtr.Zero) { Log?.Invoke($"OpenProcess err {Marshal.GetLastWin32Error()}"); return false; }
            IntPtr b = IntPtr.Zero; uint sz = 0;
            for (int i = 0; i < 40 && b == IntPtr.Zero; i++)
            {
                if (ct.IsCancellationRequested) { W32.CloseHandle(h); return false; }
                FindMod(pid, mod, out b, out sz);
                if (b == IntPtr.Zero) Thread.Sleep(200);
            }
            if (b == IntPtr.Zero) { W32.CloseHandle(h); Log?.Invoke("Base not found"); return false; }
            _h = h; _base = b; _pid = pid; _modSize = sz;
            Log?.Invoke($"Attached PID {pid} base 0x{b.ToInt64():X}");
            return true;
        }
    }

    public void Detach()
    {
        lock (_lk)
        {
            if (_h != IntPtr.Zero) W32.CloseHandle(_h);
            _h = _base = IntPtr.Zero; _pid = 0; _modSize = 0;
        }
    }

    public bool Alive()
    {
        bool entered = false;
        try
        {
            entered = Monitor.TryEnter(_lk, 50);
            if (!entered) return _h != IntPtr.Zero;
            return _h != IntPtr.Zero && W32.GetExitCodeProcess(_h, out uint c) && c == W32.ALIVE;
        }
        finally { if (entered) Monitor.Exit(_lk); }
    }

    static void FindMod(int pid, string name, out IntPtr addr, out uint size)
    {
        addr = IntPtr.Zero; size = 0;
        IntPtr s = IntPtr.Zero;
        try
        {
            s = W32.CreateToolhelp32Snapshot(W32.SNAP, (uint)pid);
            if (s == IntPtr.Zero || s == (IntPtr)(-1)) return;
            var me = new MODENTRY { dwSize = (uint)Marshal.SizeOf<MODENTRY>() };
            if (!W32.Module32FirstW(s, ref me)) return;
            do
            {
                if (me.szModule.Equals(name, StringComparison.OrdinalIgnoreCase))
                { addr = me.modBaseAddr; size = me.modBaseSize; return; }
            } while (W32.Module32NextW(s, ref me));
        }
        catch { }
        finally { if (s != IntPtr.Zero && s != (IntPtr)(-1)) W32.CloseHandle(s); }
    }

    public bool WriteRel(long off, byte[] data, int tries = 3, int delayMs = 20)
    {
        if (!On) return false;
        return WriteLoop((IntPtr)(_base.ToInt64() + off), data, tries, delayMs);
    }

    public bool WriteAbs(long addr, byte[] data, int tries = 3, int delayMs = 20)
    {
        if (!On) return false;
        return WriteLoop((IntPtr)addr, data, tries, delayMs);
    }

    bool WriteLoop(IntPtr addr, byte[] data, int tries, int delayMs)
    {
        byte[]? chk = null;
        try
        {
            chk = ArrayPool<byte>.Shared.Rent(data.Length);
            for (int t = 0; t < tries; t++)
            {
                if (t > 0) Thread.Sleep(delayMs);
                bool ok;
                lock (_lk)
                {
                    if (_h == IntPtr.Zero) return false;
                    if (!W32.WriteProcessMemory(_h, addr, data, data.Length, out int w) || w != data.Length) continue;
                    ok = W32.ReadProcessMemory(_h, addr, chk, data.Length, out int r) && r == data.Length
                         && data.AsSpan().SequenceEqual(chk.AsSpan(0, data.Length));
                }
                if (ok) return true;
            }
        }
        finally { if (chk != null) ArrayPool<byte>.Shared.Return(chk); }
        return false;
    }

    public bool WriteFast(long addr, byte[] data)
    {
        lock (_lk)
        {
            if (_h == IntPtr.Zero) return false;
            return W32.WriteProcessMemory(_h, (IntPtr)addr, data, data.Length, out int w) && w == data.Length;
        }
    }

    public byte[]? ReadAbs(long addr, int n)
    {
        lock (_lk)
        {
            if (_h == IntPtr.Zero) return null;
            var buf = new byte[n];
            return W32.ReadProcessMemory(_h, (IntPtr)addr, buf, n, out int r) && r == n ? buf : null;
        }
    }

    public long ReadPtr(long addr)
    {
        var b = ReadAbs(addr, 8);
        return b != null ? BitConverter.ToInt64(b, 0) : 0;
    }

    public int ReadInt32(long addr)
    {
        var b = ReadAbs(addr, 4);
        return b != null ? BitConverter.ToInt32(b, 0) : 0;
    }

    public void Dispose() => Detach();
}

static class FlagPrefix
{
    static readonly string[] _prefixes =
    {
        "DFString", "SFString", "FString",
        "DFFlag", "SFFlag", "DFInt", "SFInt", "DFLog", "SFLog",
        "FFlag", "FInt", "FLog"
    };

    public static ReadOnlySpan<string> All => _prefixes;

    public static string Strip(string name)
    {
        foreach (var p in _prefixes)
            if (name.Length > p.Length
                && name.StartsWith(p, StringComparison.OrdinalIgnoreCase)
                && char.IsUpper(name[p.Length]))
                return name[p.Length..];
        return name;
    }
}

sealed class FlogBank
{
    readonly MemEngine _mem;
    readonly NameResolver _resolver = new();
    readonly object _lk = new();

    long _oPointer = 0x7e71128, _oToFlag = 0x30, _oToValue = 0xc0;
    long _oNodeFwd = 0x0, _oNodeBwd = 0x8, _oNodePair = 0x10;
    long _oPairKey = 0x0, _oPairValue = 0x30;
    long _oStrData = 0x0, _oStrSize = 0x10, _oStrCap = 0x18;
    long _oFirstNode = 0x0, _oMapSize = 0x20;
    long _hashMapOff = 0x8;

    readonly Dictionary<string, long> _descMap = new();
    readonly List<string> _names = new();

    public bool Ready { get; private set; }
    public int Count { get { lock (_lk) return _descMap.Count; } }
    public IReadOnlyList<string> Names { get { lock (_lk) return _names.ToArray(); } }
    public event Action<string>? Log;

    public FlogBank(MemEngine mem) => _mem = mem;

    public void ApplyOffsets(Dictionary<string, long> offsets)
    {
        foreach (var kv in offsets)
        {
            switch (kv.Key)
            {
                case "Pointer": _oPointer = kv.Value; break;
                case "ToFlag": _oToFlag = kv.Value; break;
                case "ToValue": _oToValue = kv.Value; break;
                case "NodeForward": _oNodeFwd = kv.Value; break;
                case "NodeBackward": _oNodeBwd = kv.Value; break;
                case "NodePair": _oNodePair = kv.Value; break;
                case "Key": _oPairKey = kv.Value; break;
                case "Value": _oPairValue = kv.Value; break;
                case "Data": _oStrData = kv.Value; break;
                case "Size": _oStrSize = kv.Value; break;
                case "Capacity": _oStrCap = kv.Value; break;
                case "FirstNode": _oFirstNode = kv.Value; break;
                case "MapSize": _oMapSize = kv.Value; break;
                case "HashMapOff": _hashMapOff = kv.Value; break;
            }
        }
    }

    public bool Init()
    {
        lock (_lk)
        {
            _descMap.Clear(); _resolver.Clear(); _names.Clear(); Ready = false;
            if (!_mem.On) { Log?.Invoke("Bank: mem not attached"); return false; }

            long singleton = _mem.ReadPtr(_mem.Base + _oPointer);
            if (singleton < 0x10000) { Log?.Invoke($"Bank: bad singleton 0x{singleton:X}"); return false; }

            long mapBase = singleton + _hashMapOff;
            long sentinel = mapBase;
            long firstNode = _mem.ReadPtr(mapBase + _oFirstNode);
            int mapSize = _mem.ReadInt32(mapBase + _oMapSize);

            if (firstNode < 0x10000) { Log?.Invoke("Bank: bad firstNode"); return false; }
            if (mapSize <= 0 || mapSize > 100000) { Log?.Invoke($"Bank: suspect mapSize {mapSize}"); return false; }

            long node = firstNode;
            var visited = new HashSet<long>();
            int maxIter = Math.Min(mapSize + 100, 100000);
            int count = 0;

            for (int i = 0; i < maxIter && node != 0 && node != sentinel; i++)
            {
                if (!visited.Add(node)) break;
                long pairAddr = node + _oNodePair;
                long keyAddr = pairAddr + _oPairKey;
                string? key = ReadMsvcString(keyAddr);

                if (key != null && key.Length > 0 && key.Length < 512)
                {
                    long descPtr = _mem.ReadPtr(pairAddr + _oPairValue);
                    if (descPtr > 0x10000 && !_descMap.ContainsKey(key))
                    {
                        _descMap[key] = descPtr;
                        _resolver.Add(key);
                        _names.Add(key);
                        count++;
                    }
                }
                node = _mem.ReadPtr(node + _oNodeFwd);
            }

            Ready = count > 0;
            Log?.Invoke($"Bank: {count} flags discovered");
            return Ready;
        }
    }

    string? ReadMsvcString(long addr)
    {
        var raw = _mem.ReadAbs(addr, 32);
        if (raw == null) return null;
        long size = BitConverter.ToInt64(raw, (int)_oStrSize);
        long cap = BitConverter.ToInt64(raw, (int)_oStrCap);
        if (size < 0 || size > 4096 || cap < 0) return null;
        if (size == 0) return "";

        byte[]? strBytes;
        if (cap < 16)
        {
            if (size > 15) return null;
            strBytes = new byte[size];
            Array.Copy(raw, (int)_oStrData, strBytes, 0, (int)size);
        }
        else
        {
            long heapPtr = BitConverter.ToInt64(raw, (int)_oStrData);
            if (heapPtr < 0x10000) return null;
            strBytes = _mem.ReadAbs(heapPtr, (int)size);
            if (strBytes == null) return null;
        }
        try { return Encoding.UTF8.GetString(strBytes); } catch { return null; }
    }

    public string? Resolve(string name)
    {
        lock (_lk)
        {
            if (!Ready) return null;
            return _resolver.Resolve(name);
        }
    }

    public long GetValueAddr(string resolvedName)
    {
        lock (_lk) { return _descMap.TryGetValue(resolvedName, out long desc) ? desc + _oToValue : 0; }
    }

    public void Reset()
    {
        lock (_lk) { _descMap.Clear(); _resolver.Clear(); _names.Clear(); Ready = false; }
    }
}

sealed class OffsetStore
{
    static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(20) };
    static readonly Regex _rxUintptr = new(@"(?:inline\s+)?(?:constexpr\s+)?uintptr_t\s+(\w+)\s*=\s*(0x[0-9A-Fa-f]+);", RegexOptions.Compiled);
    static readonly Regex _rxNsFFlags = new(@"namespace\s+FFlags\s*\{([^}]+)\}", RegexOptions.Compiled | RegexOptions.Singleline);
    static readonly Regex _rxNsFFlList = new(@"namespace\s+FFlagList\s*\{([\s\S]*?)\}", RegexOptions.Compiled | RegexOptions.Singleline);
    static readonly Regex _rxNsFFlOff = new(@"namespace\s+FFlagOffsets\s*\{([\s\S]*)\}", RegexOptions.Compiled | RegexOptions.Singleline);

    readonly Dictionary<string, long> _map = new();
    readonly NameResolver _resolver = new();
    readonly HashSet<string> _seenStripped = new(StringComparer.OrdinalIgnoreCase);
    readonly List<string> _names = new();

    public IReadOnlyDictionary<string, long> Map => _map;
    public IReadOnlyList<string> Names => _names;
    public int Count => _map.Count;
    public string Cache1 { get; set; } = "";
    public string Cache2 { get; set; } = "";
    public string Url1 { get; set; } = "https://imtheo.lol/Offsets/FFlags.hpp";
    public string Url2 { get; set; } = "https://npdrlaufeimrkvdnjijl.supabase.co/functions/v1/get-offsets";
    public long FlogPointer { get; private set; }
    public Dictionary<string, long> StructOffsets { get; } = new();
    public event Action<string>? Log;

    async Task<string?> FetchUrlAsync(string url, int retries, CancellationToken ct)
    {
        for (int i = 0; i <= retries; i++)
        {
            try
            {
                if (i > 0) await Task.Delay(500 * i, ct);
                return await _http.GetStringAsync(url, ct);
            }
            catch (OperationCanceledException) { throw; }
            catch { if (i == retries) return null; }
        }
        return null;
    }

    public bool Fetch(CancellationToken ct = default)
    {
        string? body1 = null, body2 = null;
        bool cached1 = false, cached2 = false;
        try
        {
            var t1 = FetchUrlAsync(Url1, 2, ct);
            var t2 = FetchUrlAsync(Url2, 2, ct);
            Task.WhenAll(t1, t2).GetAwaiter().GetResult();
            body1 = t1.Result; body2 = t2.Result;
        }
        catch (OperationCanceledException) { return false; }
        catch (Exception ex) { Log?.Invoke("Net: " + ex.Message); }

        if (!string.IsNullOrEmpty(body1) && !string.IsNullOrEmpty(Cache1))
            try { Directory.CreateDirectory(Path.GetDirectoryName(Cache1)!); File.WriteAllText(Cache1, body1, Encoding.UTF8); } catch { }
        if (!string.IsNullOrEmpty(body2) && !string.IsNullOrEmpty(Cache2))
            try { Directory.CreateDirectory(Path.GetDirectoryName(Cache2)!); File.WriteAllText(Cache2, body2, Encoding.UTF8); } catch { }

        if (string.IsNullOrEmpty(body1) && File.Exists(Cache1))
            try { body1 = File.ReadAllText(Cache1); cached1 = true; } catch { }
        if (string.IsNullOrEmpty(body2) && File.Exists(Cache2))
            try { body2 = File.ReadAllText(Cache2); cached2 = true; } catch { }

        _map.Clear(); _resolver.Clear(); _seenStripped.Clear(); _names.Clear();
        FlogPointer = 0; StructOffsets.Clear();
        int c1 = 0, c2 = 0;
        if (!string.IsNullOrEmpty(body1)) c1 = ParseSource1(body1);
        if (!string.IsNullOrEmpty(body2)) c2 = ParseSource2(body2);
        Log?.Invoke($"Src1:{c1}{(cached1 ? "(c)" : "")} Src2:{c2}{(cached2 ? "(c)" : "")} Total:{_map.Count}");
        return _map.Count > 0;
    }

    int ParseSource1(string body)
    {
        int count = 0;
        var ns = _rxNsFFlags.Match(body);
        string region = ns.Success ? ns.Groups[1].Value : body;
        foreach (Match m in _rxUintptr.Matches(region))
        {
            if (!long.TryParse(m.Groups[2].Value.AsSpan(2), NumberStyles.HexNumber, null, out long v)) continue;
            if (v < 0x100000) continue;
            if (AddOffset(m.Groups[1].Value, v)) count++;
        }
        return count;
    }

    int ParseSource2(string body)
    {
        int count = 0;
        var flogNs = _rxNsFFlList.Match(body);
        if (flogNs.Success)
        {
            foreach (Match m in _rxUintptr.Matches(flogNs.Groups[1].Value))
            {
                if (!long.TryParse(m.Groups[2].Value.AsSpan(2), NumberStyles.HexNumber, null, out long v)) continue;
                string key = m.Groups[1].Value;
                if (key == "Pointer") FlogPointer = v;
                StructOffsets[key] = v;
            }
            body = body.Remove(flogNs.Index, flogNs.Length);
        }
        var outerNs = _rxNsFFlOff.Match(body);
        string region = outerNs.Success ? outerNs.Groups[1].Value : body;
        foreach (Match m in _rxUintptr.Matches(region))
        {
            if (!long.TryParse(m.Groups[2].Value.AsSpan(2), NumberStyles.HexNumber, null, out long v)) continue;
            string key = m.Groups[1].Value;
            if (StructOffsets.ContainsKey(key)) continue;
            if (v < 0x100000) continue;
            if (AddOffset(key, v)) count++;
        }
        return count;
    }

    bool AddOffset(string name, long offset)
    {
        if (_map.ContainsKey(name)) return false;
        _map[name] = offset;
        _resolver.Add(name);
        string s = FlagPrefix.Strip(name);
        if (_seenStripped.Add(s)) _names.Add(name);
        return true;
    }

    public string? Resolve(string n) => _resolver.Resolve(n);
    public long Offset(string resolved) => _map.TryGetValue(resolved, out long v) ? v : -1;
}

enum FType { Bool, Int, Float, String }

sealed class FlagEntry
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public FType Type { get; set; }
    public bool Enabled { get; set; } = true;
    public volatile string Status = "";

    byte[]? _cachedBytes;
    string? _cachedValue;

    public byte[] GetBytes()
    {
        string v = Value;
        if (_cachedValue == v && _cachedBytes != null) return _cachedBytes;
        var result = Type switch
        {
            FType.Bool => new[] { (byte)(v.Equals("true", StringComparison.OrdinalIgnoreCase) || v == "1" ? 1 : 0) },
            FType.Int => BitConverter.GetBytes(int.TryParse(v, NumberStyles.Any, CultureInfo.InvariantCulture, out int iv) ? iv : 0),
            FType.Float => BitConverter.GetBytes(float.TryParse(v, NumberStyles.Any, CultureInfo.InvariantCulture, out float fv) ? fv : 0f),
            _ => Encoding.UTF8.GetBytes(v + '\0')
        };
        _cachedBytes = result;
        _cachedValue = v;
        return result;
    }

    public void InvalidateCache() { _cachedBytes = null; _cachedValue = null; }

    public static FType InferFromName(string name)
    {
        foreach (var p in FlagPrefix.All)
        {
            if (name.Length > p.Length && name.StartsWith(p, StringComparison.OrdinalIgnoreCase) && char.IsUpper(name[p.Length]))
            {
                if (p.Contains("Flag", StringComparison.OrdinalIgnoreCase)) return FType.Bool;
                if (p.Contains("Int", StringComparison.OrdinalIgnoreCase) || p.Contains("Log", StringComparison.OrdinalIgnoreCase)) return FType.Int;
                if (p.Contains("String", StringComparison.OrdinalIgnoreCase)) return FType.String;
            }
        }
        return FType.String;
    }

    public static FType InferFromValue(string v)
    {
        if (string.IsNullOrWhiteSpace(v)) return FType.String;
        string lv = v.Trim().ToLowerInvariant();
        if (lv is "true" or "false") return FType.Bool;
        if (int.TryParse(v, NumberStyles.Any, CultureInfo.InvariantCulture, out _)) return FType.Int;
        if (float.TryParse(v, NumberStyles.Any, CultureInfo.InvariantCulture, out _) && v.Contains('.')) return FType.Float;
        return FType.String;
    }

    public static FType Infer(string name, string value)
    {
        var fromName = InferFromName(name);
        if (fromName != FType.String) return fromName;
        return InferFromValue(value);
    }
}

static class Theme
{
    public static readonly Color Bg = Color.FromArgb(30, 30, 46);
    public static readonly Color Surface = Color.FromArgb(36, 36, 51);
    public static readonly Color Row2 = Color.FromArgb(41, 41, 58);
    public static readonly Color Hover = Color.FromArgb(69, 71, 90);
    public static readonly Color Border = Color.FromArgb(88, 91, 112);
    public static readonly Color Fg = Color.FromArgb(205, 214, 244);
    public static readonly Color Sub = Color.FromArgb(166, 173, 200);
    public static readonly Color Accent = Color.FromArgb(137, 180, 250);
    public static readonly Color Green = Color.FromArgb(166, 227, 161);
    public static readonly Color Red = Color.FromArgb(243, 139, 168);
    public static readonly Color Peach = Color.FromArgb(250, 179, 135);
    public static readonly Color Yellow = Color.FromArgb(249, 226, 175);

    public static readonly Brush BgBr = new SolidBrush(Bg);
    public static readonly Brush SurfBr = new SolidBrush(Surface);
    public static readonly Brush HoverBr = new SolidBrush(Hover);
    public static readonly Brush FgBr = new SolidBrush(Fg);
    public static readonly Pen BorderPen = new(Border);
}

sealed class DarkRenderer : ToolStripProfessionalRenderer
{
    protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e) =>
        e.Graphics.FillRectangle(Theme.SurfBr, e.AffectedBounds);

    protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
    {
        if (e.Item.Selected && e.Item.Enabled)
            e.Graphics.FillRectangle(Theme.HoverBr, new Rectangle(Point.Empty, e.Item.Size));
    }

    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
    {
        if (!e.Item.Enabled) e.TextColor = Theme.Border;
        else if (e.Item is ToolStripStatusLabel lbl) e.TextColor = lbl.ForeColor;
        else e.TextColor = Theme.Fg;
        base.OnRenderItemText(e);
    }

    protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
    {
        int y = e.Item.Height / 2;
        e.Graphics.DrawLine(Theme.BorderPen, 4, y, e.Item.Width - 4, y);
    }

    protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
    {
        if (e.ToolStrip is StatusStrip) return;
        e.Graphics.DrawRectangle(Theme.BorderPen, e.AffectedBounds.X, e.AffectedBounds.Y,
            e.AffectedBounds.Width - 1, e.AffectedBounds.Height - 1);
    }
}

sealed class UndoStack
{
    const int MaxDepth = 50;
    readonly List<FlagSnapshot[]> _undo = new();
    readonly List<FlagSnapshot[]> _redo = new();

    public bool CanUndo => _undo.Count > 0;
    public bool CanRedo => _redo.Count > 0;

    public void Push(List<FlagEntry> flags)
    {
        _undo.Add(Snap(flags));
        if (_undo.Count > MaxDepth) _undo.RemoveAt(0);
        _redo.Clear();
    }

    public FlagSnapshot[]? Undo(List<FlagEntry> current)
    {
        if (_undo.Count == 0) return null;
        _redo.Add(Snap(current));
        var s = _undo[^1]; _undo.RemoveAt(_undo.Count - 1);
        return s;
    }

    public FlagSnapshot[]? Redo(List<FlagEntry> current)
    {
        if (_redo.Count == 0) return null;
        _undo.Add(Snap(current));
        var s = _redo[^1]; _redo.RemoveAt(_redo.Count - 1);
        return s;
    }

    static FlagSnapshot[] Snap(List<FlagEntry> flags) =>
        flags.Select(f => new FlagSnapshot(f.Name, f.Value, f.Type, f.Enabled)).ToArray();

    public record FlagSnapshot(string Name, string Value, FType Type, bool Enabled);
}

sealed class MainForm : Form
{
    readonly AppLog _log;
    readonly AppSettings _settings;
    readonly CancellationTokenSource _cts = new();
    readonly MemEngine _mem = new();
    readonly OffsetStore _off = new();
    readonly FlogBank _bank;
    readonly UndoStack _undo = new();
    readonly List<FlagEntry> _flags = new();
    readonly List<int> _modMap = new();
    readonly List<string> _topFiltered = new();
    readonly string _dir, _savePath, _settingsPath;
    readonly Font _hdrFont = new("Segoe UI Semibold", 9f);
    readonly ToolTip _tips = new() { InitialDelay = 300, ReshowDelay = 200 };

    int _monLock, _busyLock, _wdLock, _saveVer;
    volatile bool _autoApply = true, _watchdog = true, _realExit, _gameJoined;
    volatile int _lastPid;
    volatile bool _attaching;
    int _selMod = -1, _graceAttempts, _graceStableCount, _sortCol = -1;
    bool _sortAsc = true;
    string _selPreset = "";

    System.Windows.Forms.Timer _monTimer = new(), _wdTimer = new(), _graceTimer = new(),
        _searchDebounce = new(), _toastTimer = new();
    NotifyIcon _tray = new();

    SplitContainer _split = new();
    ListView _lvTop = new(), _lvBot = new();
    TextBox _searchTop = new(), _searchBot = new(), _edVal = new(), _edUpd = new();
    Label _lblTopHdr = new(), _lblBotHdr = new(), _lblSel = new(), _lblMod = new();
    Button _btnAdd = new(), _btnUpd = new(), _btnTog = new(), _btnRem = new();
    ToolStripStatusLabel _st1 = new(), _st2 = new(), _st3 = new();
    ToolStripProgressBar _progress = new();
    ContextMenuStrip _ctxTop = new(), _ctxBot = new();
    CheckBox _chkOnTop = new();

    const int GraceIntervalMs = 1500, GraceMaxAttempts = 30, GraceStableNeeded = 6;

    static readonly JsonSerializerOptions _jopt = new() { PropertyNameCaseInsensitive = true };

    public MainForm()
    {
        _dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FlagInjectorCS");
        _savePath = Path.Combine(_dir, "flags.json");
        _settingsPath = Path.Combine(_dir, "settings.json");
        _off.Cache1 = Path.Combine(_dir, "offset_cache1.hpp");
        _off.Cache2 = Path.Combine(_dir, "offset_cache2.hpp");
        Directory.CreateDirectory(_dir);

        _log = new AppLog(_dir);
        _settings = AppSettings.Load(_settingsPath);
        _bank = new FlogBank(_mem);

        _autoApply = _settings.AutoApply;
        _watchdog = _settings.Watchdog;

        Text = "FFlag Injector";
        MinimumSize = new Size(640, 520);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9f);
        BackColor = Theme.Bg;
        ForeColor = Theme.Fg;
        Icon = MakeIcon();
        AllowDrop = true;
        TopMost = _settings.AlwaysOnTop;

        if (_settings.W > 0 && _settings.H > 0) Size = new Size(_settings.W, _settings.H);
        else Size = new Size(780, 740);

        if (_settings.X >= 0 && _settings.Y >= 0)
        {
            var r = new Rectangle(_settings.X, _settings.Y, Size.Width, Size.Height);
            if (Screen.AllScreens.Any(s => s.WorkingArea.IntersectsWith(r)))
            { StartPosition = FormStartPosition.Manual; Location = new Point(_settings.X, _settings.Y); }
        }

        _mem.Log += s => { _log.Info(s); Post(() => Toast(s)); };
        _off.Log += s => { _log.Info(s); Post(() => SetStatus(2, s, Theme.Sub)); };
        _bank.Log += s => { _log.Info(s); Post(() => SetStatus(3, s, Theme.Sub)); };

        LoadFlags();

        var ct = _cts.Token;
        ThreadPool.QueueUserWorkItem(_ =>
        {
            _off.Fetch(ct);
            Post(() =>
            {
                SetStatus(2, $"{_off.Count} offsets loaded", Theme.Green);
                RefreshTop(); RefreshBot();
                TryInitBank();
            });
        });

        _monTimer.Interval = 800; _monTimer.Tick += (_, _) => MonitorTick(); _monTimer.Start();
        _wdTimer.Interval = 4000; _wdTimer.Tick += (_, _) => WatchdogTick(); _wdTimer.Enabled = _watchdog;
        _graceTimer.Interval = GraceIntervalMs; _graceTimer.Tick += (_, _) => GraceTick();
        _searchDebounce.Interval = 150; _searchDebounce.Tick += (_, _) => { _searchDebounce.Stop(); RefreshTop(); };
        _toastTimer.Tick += (_, _) => { _toastTimer.Stop(); SetStatus(3, "", Theme.Sub); };

        DragEnter += (_, e) => { if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy; };
        DragDrop += (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0
                && files[0].EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                ImportJson(files[0]);
        };

        SystemEvents.PowerModeChanged += OnPowerMode;
        SetupTray();
        BuildUI();
    }

    void Post(Action a)
    {
        try { if (!IsDisposed && IsHandleCreated) BeginInvoke(a); } catch (ObjectDisposedException) { }
    }

    bool TrySetBusy() => Interlocked.CompareExchange(ref _busyLock, 1, 0) == 0;
    void ClearBusy() => Interlocked.Exchange(ref _busyLock, 0);

    void OnPowerMode(object? s, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Resume)
            Post(() =>
            {
                if (_mem.On && !_mem.Alive())
                {
                    _graceTimer.Stop(); _gameJoined = false; _bank.Reset(); _mem.Detach();
                    _lastPid = 0; SetStatus(1, "Process lost after resume", Theme.Red);
                }
            });
    }

    void TryInitBank()
    {
        if (_bank.Ready || !_mem.On) return;
        if (_off.FlogPointer <= 0 && _off.StructOffsets.Count == 0) return;
        ThreadPool.QueueUserWorkItem(_ =>
        {
            if (_off.StructOffsets.Count > 0) _bank.ApplyOffsets(_off.StructOffsets);
            if (_bank.Init())
                Post(() =>
                {
                    Toast($"FlogBank: {_bank.Count} flags discovered");
                    SetStatus(3, $"Bank: {_bank.Count} flags", Theme.Green);
                    RefreshTop();
                });
            else
                Post(() => SetStatus(3, "Bank: init failed", Theme.Peach));
        });
    }

    void SetupTray()
    {
        var menu = new ContextMenuStrip { Renderer = new DarkRenderer(), BackColor = Theme.Surface, ForeColor = Theme.Fg };
        menu.Items.Add("Show", null, (_, _) => ShowWindow());
        menu.Items.Add("-");
        menu.Items.Add("Exit", null, (_, _) => { _realExit = true; Close(); });
        _tray.Icon = Icon;
        _tray.Text = "FFlag Injector";
        _tray.ContextMenuStrip = menu;
        _tray.DoubleClick += (_, _) => ShowWindow();
        _tray.Visible = true;
    }

    void ShowWindow() { Show(); WindowState = FormWindowState.Normal; Activate(); }

    static Icon MakeIcon()
    {
        using var bmp = new Bitmap(16, 16);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using var brush = new SolidBrush(Theme.Accent);
            g.FillEllipse(brush, 1, 1, 13, 13);
        }
        var h = bmp.GetHicon();
        var ico = (Icon)Icon.FromHandle(h).Clone();
        W32.DestroyIcon(h);
        return ico;
    }

    static void SetDouble(Control c) =>
        typeof(Control).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?.SetValue(c, true);

    static void ApplyDarkScrollbars(Control c)
    {
        try { W32.SetWindowTheme(c.Handle, "DarkMode_Explorer", null); } catch { }
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        int val = 1;
        if (W32.DwmSetWindowAttribute(Handle, 20, ref val, sizeof(int)) != 0)
            W32.DwmSetWindowAttribute(Handle, 19, ref val, sizeof(int));
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        if (_settings.Split > 0 && _settings.Split < ClientSize.Height)
            _split.SplitterDistance = _settings.Split;
        else
            _split.SplitterDistance = (int)(ClientSize.Height * 0.45);
        FixCols();
        W32.SendMessage(_searchTop.Handle, 0x1501, (IntPtr)1, "Search available flags...");
        W32.SendMessage(_searchBot.Handle, 0x1501, (IntPtr)1, "Search modified flags...");
        W32.SendMessage(_edVal.Handle, 0x1501, (IntPtr)1, "Value");
        W32.SendMessage(_edUpd.Handle, 0x1501, (IntPtr)1, "New value");
        ApplyDarkScrollbars(_lvTop);
        ApplyDarkScrollbars(_lvBot);
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        if (WindowState == FormWindowState.Minimized) { Hide(); return; }
        FixCols();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!_realExit && e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; Hide(); return; }

        _settings.AutoApply = _autoApply;
        _settings.Watchdog = _watchdog;
        _settings.AlwaysOnTop = TopMost;
        if (WindowState == FormWindowState.Normal)
        {
            _settings.X = Location.X; _settings.Y = Location.Y;
            _settings.W = Size.Width; _settings.H = Size.Height;
        }
        try { _settings.Split = _split.SplitterDistance; } catch { }
        _settings.Save(_settingsPath);

        _cts.Cancel();
        SystemEvents.PowerModeChanged -= OnPowerMode;
        _monTimer.Stop(); _wdTimer.Stop(); _graceTimer.Stop(); _searchDebounce.Stop(); _toastTimer.Stop();
        _monTimer.Dispose(); _wdTimer.Dispose(); _graceTimer.Dispose(); _searchDebounce.Dispose(); _toastTimer.Dispose();
        _tray.ContextMenuStrip?.Dispose();
        _tray.Visible = false; _tray.Dispose();
        _ctxTop.Dispose(); _ctxBot.Dispose();
        _tips.Dispose(); _hdrFont.Dispose();
        _mem.Dispose(); _log.Dispose(); _cts.Dispose();
        base.OnFormClosing(e);
    }

    protected override bool ProcessCmdKey(ref Message msg, Keys keyData) => keyData switch
    {
        Keys.Control | Keys.Shift | Keys.A => Do(ApplyAll),
        Keys.Control | Keys.O => Do(() => ImportJson()),
        Keys.Control | Keys.S => Do(ExportJson),
        Keys.Control | Keys.Z => Do(PerformUndo),
        Keys.Control | Keys.Y => Do(PerformRedo),
        Keys.Control | Keys.F => Do(() => { if (_split.Panel1.ContainsFocus) _searchTop.Focus(); else _searchBot.Focus(); }),
        Keys.F5 => Do(() => { RefreshTop(); RefreshBot(); }),
        Keys.Delete when _lvBot.Focused => Do(RemoveFlag),
        _ => base.ProcessCmdKey(ref msg, keyData)
    };

    bool Do(Action a) { a(); return true; }

    void FixCols()
    {
        if (_lvTop.Columns.Count > 0) _lvTop.Columns[0].Width = Math.Max(_lvTop.ClientSize.Width - 4, 200);
        if (_lvBot.Columns.Count >= 4)
        {
            int w = _lvBot.ClientSize.Width;
            _lvBot.Columns[0].Width = (int)(w * 0.50);
            _lvBot.Columns[1].Width = (int)(w * 0.18);
            _lvBot.Columns[2].Width = (int)(w * 0.12);
            _lvBot.Columns[3].Width = (int)(w * 0.18);
        }
    }

    Button MakeBtn(string text, int width, bool primary = false)
    {
        var b = new Button
        {
            Text = text, Width = width, Height = 30, FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand,
            BackColor = primary ? Theme.Accent : Theme.Surface,
            ForeColor = primary ? Theme.Bg : Theme.Fg,
        };
        b.FlatAppearance.BorderSize = 1;
        b.FlatAppearance.BorderColor = primary ? Theme.Accent : Theme.Border;
        b.FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(160, 200, 255) : Theme.Hover;
        return b;
    }

    void BuildUI()
    {
        var status = new StatusStrip { BackColor = Theme.Surface, Renderer = new DarkRenderer(), SizingGrip = false };
        _st1.Spring = false; _st1.AutoSize = false; _st1.Width = 290; _st1.TextAlign = ContentAlignment.MiddleLeft;
        _st1.Text = "  Not detected"; _st1.ForeColor = Theme.Red;
        _st2.Spring = false; _st2.AutoSize = false; _st2.Width = 220; _st2.TextAlign = ContentAlignment.MiddleLeft;
        _st2.Text = "  Offsets: loading..."; _st2.ForeColor = Theme.Sub;
        _st3.Spring = true; _st3.TextAlign = ContentAlignment.MiddleLeft; _st3.Text = ""; _st3.ForeColor = Theme.Sub;
        _progress.Visible = false; _progress.Width = 120; _progress.Style = ProgressBarStyle.Continuous;
        status.Items.AddRange(new ToolStripItem[] { _st1, _st2, _progress, _st3 });

        var actPanel = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 44, Padding = new Padding(6, 6, 6, 4), BackColor = Theme.Surface, WrapContents = true };
        var btnApply = MakeBtn("\u25B6 Apply All", 110, true);
        var btnImp = MakeBtn("Import", 80);
        var btnExp = MakeBtn("Export", 80);
        var btnClear = MakeBtn("Clear All", 85);
        btnClear.ForeColor = Theme.Red; btnClear.FlatAppearance.BorderColor = Theme.Red;
        btnApply.Click += (_, _) => ApplyAll();
        btnImp.Click += (_, _) => ImportJson();
        btnExp.Click += (_, _) => ExportJson();
        btnClear.Click += (_, _) => RemoveAll();

        _tips.SetToolTip(btnApply, "Apply all enabled flags (Ctrl+Shift+A)");
        _tips.SetToolTip(btnImp, "Import flags from JSON (Ctrl+O)");
        _tips.SetToolTip(btnExp, "Export flags to JSON (Ctrl+S)");
        _tips.SetToolTip(btnClear, "Remove all flags");

        var chkAuto = new CheckBox { Text = "Auto-apply", Checked = _autoApply, AutoSize = true, ForeColor = Theme.Sub, Padding = new Padding(12, 7, 0, 0) };
        var chkWd = new CheckBox { Text = "Watchdog", Checked = _watchdog, AutoSize = true, ForeColor = Theme.Sub, Padding = new Padding(4, 7, 0, 0) };
        _chkOnTop = new CheckBox { Text = "On Top", Checked = _settings.AlwaysOnTop, AutoSize = true, ForeColor = Theme.Sub, Padding = new Padding(4, 7, 0, 0) };
        chkAuto.CheckedChanged += (_, _) => _autoApply = chkAuto.Checked;
        chkWd.CheckedChanged += (_, _) => { _watchdog = chkWd.Checked; _wdTimer.Enabled = chkWd.Checked; };
        _chkOnTop.CheckedChanged += (_, _) => TopMost = _chkOnTop.Checked;

        _tips.SetToolTip(chkAuto, "Automatically apply flags when Roblox is detected");
        _tips.SetToolTip(chkWd, "Re-apply flags if they get reverted");
        _tips.SetToolTip(_chkOnTop, "Keep window above all others");

        actPanel.Controls.AddRange(new Control[] { btnApply, btnImp, btnExp, btnClear, chkAuto, chkWd, _chkOnTop });

        _split.Dock = DockStyle.Fill;
        _split.Orientation = Orientation.Horizontal;
        _split.BackColor = Theme.Border;
        _split.SplitterWidth = 3;
        _split.Panel1.BackColor = Theme.Bg;
        _split.Panel2.BackColor = Theme.Bg;

        _lblTopHdr = new Label { Text = "AVAILABLE FLAGS", Dock = DockStyle.Top, Height = 26, Padding = new Padding(6, 6, 0, 0), Font = _hdrFont, ForeColor = Theme.Sub, BackColor = Theme.Bg };
        _searchTop.Dock = DockStyle.Top; _searchTop.BackColor = Theme.Surface; _searchTop.ForeColor = Theme.Fg; _searchTop.BorderStyle = BorderStyle.FixedSingle;
        _searchTop.TextChanged += (_, _) => { _searchDebounce.Stop(); _searchDebounce.Start(); };
        _searchTop.TabIndex = 0;

        _lvTop.Dock = DockStyle.Fill; _lvTop.View = View.Details; _lvTop.FullRowSelect = true; _lvTop.MultiSelect = false;
        _lvTop.OwnerDraw = true; _lvTop.HeaderStyle = ColumnHeaderStyle.Nonclickable;
        _lvTop.BackColor = Theme.Bg; _lvTop.ForeColor = Theme.Fg; _lvTop.BorderStyle = BorderStyle.None; _lvTop.HideSelection = false;
        _lvTop.VirtualMode = true; _lvTop.VirtualListSize = 0;
        _lvTop.Columns.Add("Flag Name", 600);
        _lvTop.TabIndex = 1;
        _lvTop.RetrieveVirtualItem += (_, e) =>
        {
            e.Item = e.ItemIndex < _topFiltered.Count
                ? new ListViewItem(_topFiltered[e.ItemIndex]) { ForeColor = Theme.Fg }
                : new ListViewItem("") { ForeColor = Theme.Fg };
        };
        _lvTop.SearchForVirtualItem += (_, e) =>
        {
            if (string.IsNullOrEmpty(e.Text)) return;
            for (int i = 0; i < _topFiltered.Count; i++)
                if (_topFiltered[i].StartsWith(e.Text, StringComparison.OrdinalIgnoreCase))
                { e.Index = i; return; }
        };
        _lvTop.SelectedIndexChanged += (_, _) => TopClick();
        _lvTop.DoubleClick += (_, _) => { TopClick(); if (_selPreset != "") _edVal.Focus(); };
        _lvTop.DrawColumnHeader += LvDrawHeader;
        _lvTop.DrawItem += (_, _) => { };
        _lvTop.DrawSubItem += LvDrawSub;
        _lvTop.HandleCreated += (_, _) => ApplyDarkScrollbars(_lvTop);
        SetDouble(_lvTop);

        _ctxTop.Renderer = new DarkRenderer(); _ctxTop.BackColor = Theme.Surface; _ctxTop.ForeColor = Theme.Fg;
        _ctxTop.Items.Add("Add selected flag", null, (_, _) => AddFlag());
        _ctxTop.Items.Add("Copy name", null, (_, _) => { if (_selPreset != "") Clipboard.SetText(_selPreset); });
        _ctxTop.Opening += (_, e) => { if (_selPreset == "") e.Cancel = true; };
        _lvTop.ContextMenuStrip = _ctxTop;

        var addRow = new Panel { Dock = DockStyle.Bottom, Height = 38, BackColor = Theme.Surface, Padding = new Padding(6, 4, 6, 4) };
        _lblSel = new Label { Text = "No flag selected", AutoSize = false, Width = 220, Height = 28, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.Sub, AutoEllipsis = true };
        _edVal.Width = 180; _edVal.BackColor = Theme.Bg; _edVal.ForeColor = Theme.Fg; _edVal.BorderStyle = BorderStyle.FixedSingle;
        _edVal.TextChanged += (_, _) => _btnAdd.Enabled = _selPreset != "" && _edVal.Text.Trim() != "";
        _edVal.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; AddFlag(); } };
        _edVal.TabIndex = 2;
        _btnAdd = MakeBtn("Add", 60); _btnAdd.Enabled = false; _btnAdd.Click += (_, _) => AddFlag(); _btnAdd.TabIndex = 3;
        _tips.SetToolTip(_btnAdd, "Add this flag to your list");
        var addFlow = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, AutoSize = false };
        addFlow.Controls.AddRange(new Control[] { _lblSel, _edVal, _btnAdd });
        addRow.Controls.Add(addFlow);

        _split.Panel1.Controls.Add(_lvTop);
        _split.Panel1.Controls.Add(addRow);
        _split.Panel1.Controls.Add(_searchTop);
        _split.Panel1.Controls.Add(_lblTopHdr);

        _lblBotHdr = new Label { Text = "MODIFIED FLAGS", Dock = DockStyle.Top, Height = 26, Padding = new Padding(6, 6, 0, 0), Font = _hdrFont, ForeColor = Theme.Sub, BackColor = Theme.Bg };
        _tips.SetToolTip(_lblBotHdr, "Colors: Green=Applied  Orange=No Offset  Red=Failed  Gray=Disabled");
        _searchBot.Dock = DockStyle.Top; _searchBot.BackColor = Theme.Surface; _searchBot.ForeColor = Theme.Fg; _searchBot.BorderStyle = BorderStyle.FixedSingle;
        _searchBot.TextChanged += (_, _) => RefreshBot();
        _searchBot.TabIndex = 4;

        _lvBot.Dock = DockStyle.Fill; _lvBot.View = View.Details; _lvBot.FullRowSelect = true; _lvBot.MultiSelect = false;
        _lvBot.OwnerDraw = true; _lvBot.HeaderStyle = ColumnHeaderStyle.Clickable;
        _lvBot.BackColor = Theme.Bg; _lvBot.ForeColor = Theme.Fg; _lvBot.BorderStyle = BorderStyle.None; _lvBot.HideSelection = false;
        _lvBot.Columns.Add("Flag", 300); _lvBot.Columns.Add("Value", 100); _lvBot.Columns.Add("Type", 60); _lvBot.Columns.Add("Status", 100);
        _lvBot.TabIndex = 5;
        _lvBot.SelectedIndexChanged += (_, _) => BotClick();
        _lvBot.DoubleClick += (_, _) => { BotClick(); if (_selMod >= 0) _edUpd.Focus(); };
        _lvBot.ColumnClick += (_, e) =>
        {
            if (_sortCol == e.Column) _sortAsc = !_sortAsc;
            else { _sortCol = e.Column; _sortAsc = true; }
            RefreshBot();
        };
        _lvBot.DrawColumnHeader += LvDrawHeader;
        _lvBot.DrawItem += (_, _) => { };
        _lvBot.DrawSubItem += LvDrawSub;
        _lvBot.HandleCreated += (_, _) => ApplyDarkScrollbars(_lvBot);
        SetDouble(_lvBot);

        _ctxBot.Renderer = new DarkRenderer(); _ctxBot.BackColor = Theme.Surface; _ctxBot.ForeColor = Theme.Fg;
        _ctxBot.Items.Add("Apply this flag", null, (_, _) => ApplySingleSelected());
        _ctxBot.Items.Add("Update value", null, (_, _) => UpdateFlag());
        _ctxBot.Items.Add("Toggle on/off", null, (_, _) => ToggleFlag());
        _ctxBot.Items.Add("Copy name", null, (_, _) => { if (_selMod >= 0) Clipboard.SetText(_flags[_selMod].Name); });
        _ctxBot.Items.Add("Copy value", null, (_, _) => { if (_selMod >= 0) Clipboard.SetText(_flags[_selMod].Value); });
        _ctxBot.Items.Add("-");
        _ctxBot.Items.Add("Enable all", null, (_, _) => BulkEnable(true));
        _ctxBot.Items.Add("Disable all", null, (_, _) => BulkEnable(false));
        _ctxBot.Items.Add("-");
        _ctxBot.Items.Add("Remove", null, (_, _) => RemoveFlag());
        _ctxBot.Opening += (_, e) => { if (_selMod < 0) e.Cancel = true; };
        _lvBot.ContextMenuStrip = _ctxBot;

        var modRow = new Panel { Dock = DockStyle.Bottom, Height = 38, BackColor = Theme.Surface, Padding = new Padding(6, 4, 6, 4) };
        _lblMod = new Label { Text = "No flag selected", AutoSize = false, Width = 200, Height = 28, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.Sub, AutoEllipsis = true };
        _edUpd.Width = 140; _edUpd.BackColor = Theme.Bg; _edUpd.ForeColor = Theme.Fg; _edUpd.BorderStyle = BorderStyle.FixedSingle;
        _edUpd.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; UpdateFlag(); } };
        _edUpd.TabIndex = 6;
        _btnUpd = MakeBtn("Update", 70); _btnUpd.Enabled = false; _btnUpd.Click += (_, _) => UpdateFlag(); _btnUpd.TabIndex = 7;
        _btnTog = MakeBtn("Disable", 75); _btnTog.Enabled = false; _btnTog.Click += (_, _) => ToggleFlag(); _btnTog.TabIndex = 8;
        _btnRem = MakeBtn("Remove", 70); _btnRem.Enabled = false; _btnRem.ForeColor = Theme.Red; _btnRem.FlatAppearance.BorderColor = Theme.Red;
        _btnRem.Click += (_, _) => RemoveFlag(); _btnRem.TabIndex = 9;
        _tips.SetToolTip(_btnUpd, "Update value of selected flag");
        _tips.SetToolTip(_btnTog, "Enable or disable selected flag");
        _tips.SetToolTip(_btnRem, "Remove selected flag (Delete)");
        var modFlow = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, AutoSize = false };
        modFlow.Controls.AddRange(new Control[] { _lblMod, _edUpd, _btnUpd, _btnTog, _btnRem });
        modRow.Controls.Add(modFlow);

        _split.Panel2.Controls.Add(_lvBot);
        _split.Panel2.Controls.Add(modRow);
        _split.Panel2.Controls.Add(_searchBot);
        _split.Panel2.Controls.Add(_lblBotHdr);

        Controls.Add(_split);
        Controls.Add(actPanel);
        Controls.Add(status);
        RefreshTop(); RefreshBot();
    }

    void LvDrawHeader(object? s, DrawListViewColumnHeaderEventArgs e)
    {
        e.Graphics.FillRectangle(Theme.SurfBr, e.Bounds);
        string txt = e.Header!.Text;
        if (s == _lvBot && _sortCol == e.ColumnIndex)
            txt += _sortAsc ? " \u25B2" : " \u25BC";
        TextRenderer.DrawText(e.Graphics, txt, Font, e.Bounds, Theme.Sub,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.LeftAndRightPadding);
        e.Graphics.DrawLine(Theme.BorderPen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
    }

    void LvDrawSub(object? s, DrawListViewSubItemEventArgs e)
    {
        if (e.Item == null || e.SubItem == null) return;
        Color bg = e.Item.Selected ? Theme.Hover : (e.ItemIndex % 2 == 0 ? Theme.Bg : Theme.Row2);
        using (var brush = new SolidBrush(bg))
            e.Graphics.FillRectangle(brush, e.Bounds);
        var fg = e.SubItem.ForeColor;
        if (e.Item.Selected) fg = Theme.Fg;
        TextRenderer.DrawText(e.Graphics, e.SubItem.Text, Font, e.Bounds, fg,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.LeftAndRightPadding);
    }

    void SetStatus(int idx, string txt, Color? col = null)
    {
        if (InvokeRequired) { Post(() => SetStatus(idx, txt, col)); return; }
        switch (idx)
        {
            case 1: _st1.Text = "  " + txt; if (col.HasValue) _st1.ForeColor = col.Value; break;
            case 2: _st2.Text = "  " + txt; if (col.HasValue) _st2.ForeColor = col.Value; break;
            case 3: _st3.Text = txt; if (col.HasValue) _st3.ForeColor = col.Value; break;
        }
    }

    void Toast(string msg, int ms = 3500)
    {
        SetStatus(3, msg, Theme.Sub);
        _toastTimer.Stop();
        _toastTimer.Interval = ms;
        _toastTimer.Start();
    }

    void MonitorTick()
    {
        if (Interlocked.CompareExchange(ref _monLock, 1, 0) != 0) return;
        if (_attaching) { Interlocked.Exchange(ref _monLock, 0); return; }

        Task.Run(() =>
        {
            int pid = 0;
            try
            {
                var procs = Process.GetProcessesByName("RobloxPlayerBeta");
                int bestPid = 0;
                bool hasWindow = false;
                foreach (var p in procs)
                {
                    try
                    {
                        if (!p.HasExited)
                        {
                            if (p.MainWindowHandle != IntPtr.Zero && !hasWindow)
                            { bestPid = p.Id; hasWindow = true; }
                            else if (bestPid == 0)
                                bestPid = p.Id;
                        }
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
                pid = bestPid;
            }
            catch { }
            return pid;
        }).ContinueWith(t =>
        {
            try
            {
                int result = 0;
                try { result = t.Result; } catch { }
                Post(() => HandleMonResult(result));
            }
            finally { Interlocked.Exchange(ref _monLock, 0); }
        });
    }

    void HandleMonResult(int pid)
    {
        if (pid != 0 && pid != _lastPid)
        {
            _lastPid = pid;
            _gameJoined = false;
            _graceTimer.Stop();
            _bank.Reset();
            _attaching = true;
            SetStatus(1, $"Attaching PID {pid}...", Theme.Yellow);
            _log.Info($"Detected PID {pid}");
            ThreadPool.QueueUserWorkItem(_ =>
            {
                bool ok = false;
                try { ok = _mem.Attach(pid, "RobloxPlayerBeta.exe", _cts.Token); }
                finally { _attaching = false; }
                Post(() =>
                {
                    if (ok)
                    {
                        SetStatus(1, $"PID {pid} \u2014 0x{_mem.Base:X}", Theme.Green);
                        _tray.Text = $"FFlag Injector \u2014 PID {pid}";
                        TryInitBank();
                        if (_autoApply && _off.Count > 0) StartGrace();
                    }
                    else
                    {
                        SetStatus(1, "Attach failed", Theme.Red);
                        _lastPid = 0;
                    }
                });
            });
        }
        else if (pid == 0 && _lastPid != 0)
        {
            _graceTimer.Stop(); _gameJoined = false; _bank.Reset(); _mem.Detach();
            _lastPid = 0;
            SetStatus(1, "Not detected", Theme.Red);
            _tray.Text = "FFlag Injector";
            Toast("Roblox disconnected");
            _log.Info("Process exited");
        }
        else if (pid != 0 && !_attaching && _mem.On && !_mem.Alive())
        {
            _graceTimer.Stop(); _gameJoined = false; _bank.Reset(); _mem.Detach();
            _lastPid = 0;
            SetStatus(1, "Process exited", Theme.Red);
            _log.Warn("Process exited unexpectedly");
        }
    }

    void StartGrace()
    {
        _graceTimer.Stop();
        _graceAttempts = 0; _graceStableCount = 0; _gameJoined = false;
        SetStatus(3, "Waiting for game join...", Theme.Yellow);
        _graceTimer.Start();
    }

    void GraceTick()
    {
        _graceAttempts++;
        if (!_mem.On || !_mem.Alive()) { _graceTimer.Stop(); _gameJoined = false; return; }

        bool windowReady = false;
        try
        {
            using var p = Process.GetProcessById(_mem.Pid);
            windowReady = p.MainWindowHandle != IntPtr.Zero && !p.HasExited;
        }
        catch { }

        if (windowReady) _graceStableCount++; else _graceStableCount = 0;

        if (_graceStableCount >= GraceStableNeeded)
        {
            _graceTimer.Stop(); _gameJoined = true;
            if (_mem.On && _autoApply && (_off.Count > 0 || _bank.Ready))
            { SetStatus(3, "Game joined, applying...", Theme.Green); ApplyAll(); }
            _tray.ShowBalloonTip(3000, "FFlag Injector", "Game detected, applying flags", ToolTipIcon.Info);
            return;
        }
        if (_graceAttempts >= GraceMaxAttempts)
        {
            _graceTimer.Stop(); _gameJoined = true;
            if (_mem.On && _autoApply && (_off.Count > 0 || _bank.Ready))
            { SetStatus(3, "Grace timeout, applying...", Theme.Yellow); ApplyAll(); }
            return;
        }
        string phase = windowReady ? $"Stabilizing {_graceStableCount}/{GraceStableNeeded}" : "Waiting for window";
        SetStatus(3, $"Grace {_graceAttempts}/{GraceMaxAttempts}: {phase}", Theme.Yellow);
    }

    bool ResolveFlagAddr(FlagEntry f, out long addr, out string method)
    {
        addr = 0; method = "";
        var r = _off.Resolve(f.Name);
        if (r != null)
        {
            long o = _off.Offset(r);
            if (o > 0) { addr = _mem.Base + o; method = "offset"; return true; }
        }
        if (_bank.Ready)
        {
            var br = _bank.Resolve(f.Name);
            if (br != null)
            {
                long va = _bank.GetValueAddr(br);
                if (va > 0) { addr = va; method = "bank"; return true; }
            }
        }
        return false;
    }

    void WatchdogTick()
    {
        if (!_watchdog || !_gameJoined || !_mem.On) return;
        if (Interlocked.CompareExchange(ref _wdLock, 1, 0) != 0) return;
        if (_busyLock != 0) { Interlocked.Exchange(ref _wdLock, 0); return; }

        var snapshot = _flags.Where(f => f.Enabled).ToArray();
        ThreadPool.QueueUserWorkItem(state =>
        {
            try
            {
                if (_busyLock != 0 || !_gameJoined) return;
                int fix = 0;
                foreach (var f in snapshot)
                {
                    if (_busyLock != 0 || _cts.IsCancellationRequested) break;
                    if (!ResolveFlagAddr(f, out long addr, out _)) continue;
                    var want = f.GetBytes();
                    var cur = _mem.ReadAbs(addr, want.Length);
                    if (cur != null && want.AsSpan().SequenceEqual(cur)) continue;
                    if (_mem.WriteFast(addr, want)) fix++;
                }
                if (fix > 0)
                {
                    _log.Info($"Watchdog re-applied {fix} flag(s)");
                    Post(() => { Toast($"Watchdog re-applied {fix} flag(s)"); RefreshBot(); });
                }
            }
            finally { Interlocked.Exchange(ref _wdLock, 0); }
        });
    }

    void ApplyAll()
    {
        if (!_mem.On) { Toast("Roblox not attached"); return; }
        if (!TrySetBusy()) { Toast("Apply already in progress"); return; }
        var snapshot = _flags.ToArray();
        int total = snapshot.Length;
        Post(() => { _progress.Maximum = Math.Max(total, 1); _progress.Value = 0; _progress.Visible = true; });

        ThreadPool.QueueUserWorkItem(_ =>
        {
            try
            {
                int ok = 0, fail = 0, skip = 0, dis = 0;
                for (int i = 0; i < snapshot.Length; i++)
                {
                    if (_cts.IsCancellationRequested) break;
                    var f = snapshot[i];
                    if (!f.Enabled) { dis++; }
                    else if (!ResolveFlagAddr(f, out long addr, out string method))
                    { f.Status = "No Offset"; skip++; }
                    else if (_mem.WriteFast(addr, f.GetBytes()))
                    { f.Status = $"Applied ({method})"; ok++; }
                    else { f.Status = "Failed"; fail++; }

                    if (i % 10 == 0 || i == snapshot.Length - 1)
                    {
                        int prog = i + 1;
                        Post(() => { try { _progress.Value = Math.Min(prog, _progress.Maximum); } catch { } });
                    }
                }
                _log.Info($"ApplyAll: ok={ok} fail={fail} skip={skip} dis={dis}");
                Post(() =>
                {
                    _progress.Visible = false;
                    RefreshBot();
                    Toast($"Applied:{ok}  Failed:{fail}  Skip:{skip}  Off:{dis}", 4000);
                });
            }
            finally { ClearBusy(); }
        });
    }

    void ApplySingleSelected()
    {
        if (_selMod < 0 || _selMod >= _flags.Count) return;
        var f = _flags[_selMod];
        if (!f.Enabled) { Toast("Flag is disabled"); return; }
        if (!_mem.On) { Toast("Roblox not attached"); return; }
        ThreadPool.QueueUserWorkItem(_ =>
        {
            bool ok = ApplySingle(f);
            Post(() => { RefreshBot(); Toast(ok ? $"Applied: {f.Name}" : $"Failed: {f.Name}"); });
        });
    }

    bool ApplySingle(FlagEntry f)
    {
        if (!_mem.On) return false;
        if (!ResolveFlagAddr(f, out long addr, out string method))
        { f.Status = "No Offset"; return false; }
        if (_mem.WriteAbs(addr, f.GetBytes()))
        { f.Status = $"Applied ({method})"; return true; }
        f.Status = "Failed"; return false;
    }

    void RefreshTop()
    {
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var existingStripped = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in _flags)
        {
            existing.Add(f.Name);
            existingStripped.Add(FlagPrefix.Strip(f.Name));
        }

        string filter = _searchTop.Text;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _topFiltered.Clear();

        foreach (var n in _off.Names)
        {
            if (existing.Contains(n)) continue;
            string s = FlagPrefix.Strip(n);
            if (existingStripped.Contains(s)) continue;
            if (filter.Length > 0 && n.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0
                && s.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;
            if (seen.Add(s)) _topFiltered.Add(n);
        }

        if (_bank.Ready)
        {
            foreach (var n in _bank.Names)
            {
                if (existing.Contains(n)) continue;
                string s = FlagPrefix.Strip(n);
                if (existingStripped.Contains(s)) continue;
                if (!seen.Add(s)) continue;
                if (filter.Length > 0 && n.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0
                    && s.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;
                _topFiltered.Add(n);
            }
        }

        _topFiltered.Sort(StringComparer.OrdinalIgnoreCase);
        _lvTop.SelectedIndices.Clear();
        _lvTop.VirtualListSize = _topFiltered.Count;
        _lvTop.Invalidate();
        _lblTopHdr.Text = $"AVAILABLE FLAGS ({_topFiltered.Count})";
        _selPreset = ""; _lblSel.Text = "No flag selected"; _btnAdd.Enabled = false;
    }

    void RefreshBot()
    {
        _lvBot.BeginUpdate(); _lvBot.Items.Clear(); _modMap.Clear(); _selMod = -1;
        string filter = _searchBot.Text;
        var items = new List<(ListViewItem item, int idx)>();

        for (int i = 0; i < _flags.Count; i++)
        {
            var f = _flags[i];
            if (filter.Length > 0 && f.Name.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0
                && FlagPrefix.Strip(f.Name).IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;
            string st = f.Enabled ? (f.Status == "" ? "Active" : f.Status) : "Disabled";
            if (f.Enabled && st == "Active" && _off.Resolve(f.Name) == null
                && (!_bank.Ready || _bank.Resolve(f.Name) == null))
                st = "No Offset";
            var item = new ListViewItem(new[] { f.Name, f.Value, f.Type.ToString(), st });
            if (!f.Enabled) item.ForeColor = Theme.Border;
            else if (st.StartsWith("Applied")) item.ForeColor = Theme.Green;
            else if (st == "Failed") item.ForeColor = Theme.Red;
            else if (st == "No Offset") item.ForeColor = Theme.Peach;
            else item.ForeColor = Theme.Fg;
            items.Add((item, i));
        }

        if (_sortCol >= 0 && _sortCol < 4)
        {
            items.Sort((a, b) =>
            {
                int cmp = string.Compare(a.item.SubItems[_sortCol].Text, b.item.SubItems[_sortCol].Text,
                    StringComparison.OrdinalIgnoreCase);
                return _sortAsc ? cmp : -cmp;
            });
        }

        foreach (var (item, idx) in items) { _lvBot.Items.Add(item); _modMap.Add(idx); }
        _lvBot.EndUpdate();
        _lblBotHdr.Text = $"MODIFIED FLAGS ({_flags.Count})";
        _lblMod.Text = "No flag selected"; _edUpd.Text = "";
        _btnUpd.Enabled = _btnTog.Enabled = _btnRem.Enabled = false;
    }

    void TopClick()
    {
        if (_lvTop.SelectedIndices.Count == 0 || _lvTop.SelectedIndices[0] >= _topFiltered.Count)
        { _selPreset = ""; _lblSel.Text = "No flag selected"; _btnAdd.Enabled = false; return; }
        _selPreset = _topFiltered[_lvTop.SelectedIndices[0]];
        _lblSel.Text = _selPreset;
        _btnAdd.Enabled = _edVal.Text.Trim().Length > 0;
    }

    void BotClick()
    {
        if (_lvBot.SelectedItems.Count == 0 || _lvBot.SelectedIndices[0] >= _modMap.Count)
        {
            _selMod = -1; _lblMod.Text = "No flag selected"; _edUpd.Text = "";
            _btnUpd.Enabled = _btnTog.Enabled = _btnRem.Enabled = false; return;
        }
        _selMod = _modMap[_lvBot.SelectedIndices[0]];
        if (_selMod >= _flags.Count) { _selMod = -1; return; }
        var f = _flags[_selMod];
        _lblMod.Text = $"{f.Name} = {f.Value}";
        _edUpd.Text = f.Value;
        _btnUpd.Enabled = _btnTog.Enabled = _btnRem.Enabled = true;
        _btnTog.Text = f.Enabled ? "Disable" : "Enable";
    }

    void AddFlag()
    {
        string v = _edVal.Text.Trim();
        if (_selPreset == "" || v == "") return;
        if (_flags.Any(f => f.Name.Equals(_selPreset, StringComparison.OrdinalIgnoreCase)))
        { Toast($"'{_selPreset}' already exists"); return; }
        var t = FlagEntry.Infer(_selPreset, v);
        if (t == FType.Int && !int.TryParse(v, NumberStyles.Any, CultureInfo.InvariantCulture, out _)) { Toast("Invalid integer"); return; }
        if (t == FType.Float && !float.TryParse(v, NumberStyles.Any, CultureInfo.InvariantCulture, out _)) { Toast("Invalid float"); return; }

        _undo.Push(_flags);
        var fe = new FlagEntry { Name = _selPreset, Value = v, Type = t };
        _flags.Add(fe); SaveFlags(); RefreshTop(); RefreshBot(); _edVal.Text = "";
        if (_autoApply && _gameJoined && _mem.On)
            ThreadPool.QueueUserWorkItem(_ => { ApplySingle(fe); Post(() => RefreshBot()); });
        Toast($"Added: {fe.Name} = {v} [{t}]");
        _log.Info($"Added flag: {fe.Name}={v}");
    }

    void UpdateFlag()
    {
        if (_selMod < 0 || _selMod >= _flags.Count) return;
        string nv = _edUpd.Text.Trim();
        if (nv == "") { Toast("Value cannot be empty"); return; }
        var f = _flags[_selMod];
        var nt = FlagEntry.Infer(f.Name, nv);
        if (nt == FType.Int && !int.TryParse(nv, NumberStyles.Any, CultureInfo.InvariantCulture, out _)) { Toast("Invalid integer"); return; }
        if (nt == FType.Float && !float.TryParse(nv, NumberStyles.Any, CultureInfo.InvariantCulture, out _)) { Toast("Invalid float"); return; }

        _undo.Push(_flags);
        f.Value = nv; f.Type = nt; f.InvalidateCache();
        if (f.Enabled && _gameJoined && _mem.On)
            ThreadPool.QueueUserWorkItem(_ => { ApplySingle(f); Post(() => RefreshBot()); });
        SaveFlags(); RefreshBot(); Toast($"Updated: {f.Name} = {nv}");
    }

    void ToggleFlag()
    {
        if (_selMod < 0 || _selMod >= _flags.Count) return;
        _undo.Push(_flags);
        var f = _flags[_selMod]; f.Enabled = !f.Enabled;
        SaveFlags(); RefreshBot(); Toast($"{(f.Enabled ? "Enabled" : "Disabled")}: {f.Name}");
    }

    void RemoveFlag()
    {
        if (_selMod < 0 || _selMod >= _flags.Count) return;
        _undo.Push(_flags);
        string n = _flags[_selMod].Name; _flags.RemoveAt(_selMod); _selMod = -1;
        SaveFlags(); RefreshTop(); RefreshBot(); Toast($"Removed: {n}");
    }

    void RemoveAll()
    {
        if (_flags.Count == 0) return;
        if (MessageBox.Show($"Remove all {_flags.Count} flags?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        _undo.Push(_flags);
        _flags.Clear(); _selMod = -1; SaveFlags(); RefreshTop(); RefreshBot(); Toast("All flags removed");
    }

    void BulkEnable(bool enable)
    {
        if (_flags.Count == 0) return;
        _undo.Push(_flags);
        foreach (var f in _flags) f.Enabled = enable;
        SaveFlags(); RefreshBot(); Toast(enable ? "All flags enabled" : "All flags disabled");
    }

    void PerformUndo()
    {
        var snap = _undo.Undo(_flags);
        if (snap == null) { Toast("Nothing to undo"); return; }
        RestoreSnapshot(snap);
        SaveFlags(); RefreshTop(); RefreshBot(); Toast("Undo");
    }

    void PerformRedo()
    {
        var snap = _undo.Redo(_flags);
        if (snap == null) { Toast("Nothing to redo"); return; }
        RestoreSnapshot(snap);
        SaveFlags(); RefreshTop(); RefreshBot(); Toast("Redo");
    }

    void RestoreSnapshot(UndoStack.FlagSnapshot[] snap)
    {
        _flags.Clear(); _selMod = -1;
        foreach (var s in snap)
            _flags.Add(new FlagEntry { Name = s.Name, Value = s.Value, Type = s.Type, Enabled = s.Enabled });
    }

    void ImportJson(string? path = null)
    {
        if (path == null)
        {
            using var dlg = new OpenFileDialog { Filter = "JSON|*.json", Title = "Import FFlags JSON" };
            if (dlg.ShowDialog() != DialogResult.OK) return;
            path = dlg.FileName;
        }
        try
        {
            string raw = File.ReadAllText(path, Encoding.UTF8);
            using var doc = JsonDocument.Parse(raw, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });

            _undo.Push(_flags);
            var existByName = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var existByStripped = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < _flags.Count; i++)
            {
                existByName[_flags[i].Name] = i;
                existByStripped[FlagPrefix.Strip(_flags[i].Name)] = i;
            }

            int added = 0, updated = 0;

            if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    string jn = prop.Name;
                    string val;
                    switch (prop.Value.ValueKind)
                    {
                        case JsonValueKind.True: val = "true"; break;
                        case JsonValueKind.False: val = "false"; break;
                        case JsonValueKind.Number: val = prop.Value.GetRawText(); break;
                        case JsonValueKind.String: val = prop.Value.GetString() ?? ""; break;
                        default: continue;
                    }
                    ProcessImportEntry(jn, val, existByName, existByStripped, ref added, ref updated);
                }
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var elem in doc.RootElement.EnumerateArray())
                {
                    if (elem.ValueKind != JsonValueKind.Object) continue;
                    string jn = ""; string val = ""; bool enabled = true; string typeStr = "";
                    if (elem.TryGetProperty("n", out var nProp)) jn = nProp.GetString() ?? "";
                    else if (elem.TryGetProperty("Name", out var nameProp)) jn = nameProp.GetString() ?? "";
                    if (elem.TryGetProperty("v", out var vProp)) val = vProp.GetString() ?? "";
                    else if (elem.TryGetProperty("Value", out var valProp)) val = valProp.GetString() ?? "";
                    if (elem.TryGetProperty("t", out var tProp)) typeStr = tProp.GetString() ?? "";
                    if (elem.TryGetProperty("e", out var eProp) && eProp.ValueKind == JsonValueKind.False) enabled = false;
                    if (string.IsNullOrEmpty(jn)) continue;

                    string? resolved = _off.Resolve(jn) ?? (_bank.Ready ? _bank.Resolve(jn) : null) ?? jn;
                    var t = Enum.TryParse<FType>(typeStr, true, out var parsed) ? parsed : FlagEntry.Infer(resolved, val);
                    string rs = FlagPrefix.Strip(resolved);
                    int idx = -1;
                    if (existByName.TryGetValue(resolved, out int i1)) idx = i1;
                    else if (existByStripped.TryGetValue(rs, out int i2)) idx = i2;

                    if (idx >= 0) { _flags[idx].Value = val; _flags[idx].Type = t; _flags[idx].Enabled = enabled; updated++; }
                    else
                    {
                        _flags.Add(new FlagEntry { Name = resolved, Value = val, Type = t, Enabled = enabled });
                        int ni = _flags.Count - 1;
                        existByName[resolved] = ni; existByStripped[rs] = ni;
                        added++;
                    }
                }
            }

            if (added + updated == 0) { Toast("No matching flags found"); return; }
            SaveFlags(); RefreshTop(); RefreshBot();
            if (_autoApply && _gameJoined && _mem.On) ApplyAll();
            Toast($"Imported: +{added} ~{updated}");
            _log.Info($"Imported from {path}: +{added} ~{updated}");
        }
        catch (Exception ex)
        {
            Toast("Import error: " + ex.Message);
            _log.Error("Import: " + ex.Message);
        }
    }

    void ProcessImportEntry(string jn, string val, Dictionary<string, int> byName, Dictionary<string, int> byStripped, ref int added, ref int updated)
    {
        string? resolved = _off.Resolve(jn) ?? (_bank.Ready ? _bank.Resolve(jn) : null) ?? jn;
        var t = FlagEntry.Infer(resolved, val);
        string rs = FlagPrefix.Strip(resolved);
        int idx = -1;
        if (byName.TryGetValue(resolved, out int i1)) idx = i1;
        else if (byStripped.TryGetValue(rs, out int i2)) idx = i2;

        if (idx >= 0) { _flags[idx].Value = val; _flags[idx].Type = t; _flags[idx].Enabled = true; updated++; }
        else
        {
            _flags.Add(new FlagEntry { Name = resolved, Value = val, Type = t });
            int ni = _flags.Count - 1;
            byName[resolved] = ni; byStripped[rs] = ni;
            added++;
        }
    }

    void ExportJson()
    {
        if (_flags.Count == 0) { Toast("No flags to export"); return; }
        using var dlg = new SaveFileDialog { Filter = "JSON|*.json", FileName = "flags.json" };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        try
        {
            using var ms = new MemoryStream();
            using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
            {
                w.WriteStartObject();
                foreach (var f in _flags)
                {
                    switch (f.Type)
                    {
                        case FType.Bool:
                            w.WriteBoolean(f.Name, f.Value.Equals("true", StringComparison.OrdinalIgnoreCase) || f.Value == "1");
                            break;
                        case FType.Int:
                            if (int.TryParse(f.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out int iv))
                                w.WriteNumber(f.Name, iv);
                            else w.WriteString(f.Name, f.Value);
                            break;
                        case FType.Float:
                            if (float.TryParse(f.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out float fv))
                                w.WriteNumber(f.Name, fv);
                            else w.WriteString(f.Name, f.Value);
                            break;
                        default:
                            w.WriteString(f.Name, f.Value);
                            break;
                    }
                }
                w.WriteEndObject();
            }
            File.WriteAllBytes(dlg.FileName, ms.ToArray());
            Toast($"Exported {_flags.Count} flags");
            _log.Info($"Exported {_flags.Count} flags to {dlg.FileName}");
        }
        catch (Exception ex) { Toast("Export error: " + ex.Message); }
    }

    void SaveFlags()
    {
        int ver = Interlocked.Increment(ref _saveVer);
        var dtos = _flags.Select(f => new FlagDto { Name = f.Name, Value = f.Value, Type = f.Type.ToString(), Enabled = f.Enabled }).ToArray();
        string data = JsonSerializer.Serialize(dtos);
        string sp = _savePath;
        Task.Run(() =>
        {
            if (Volatile.Read(ref _saveVer) != ver) return;
            try
            {
                string tmp = sp + ".tmp";
                File.WriteAllText(tmp, data, new UTF8Encoding(false));
                if (File.Exists(sp)) try { File.Copy(sp, sp + ".bak", true); } catch { }
                File.Move(tmp, sp, true);
            }
            catch (Exception ex) { _log.Error("Save: " + ex.Message); }
        });
    }

    void LoadFlags()
    {
        if (!File.Exists(_savePath)) return;
        try
        {
            string raw = File.ReadAllText(_savePath, Encoding.UTF8);
            var dtos = JsonSerializer.Deserialize<FlagDto[]>(raw, _jopt);
            if (dtos == null) return;
            foreach (var d in dtos)
            {
                if (string.IsNullOrWhiteSpace(d.Name)) continue;
                Enum.TryParse(d.Type, true, out FType t);
                _flags.Add(new FlagEntry { Name = d.Name, Value = d.Value, Type = t, Enabled = d.Enabled });
            }
            _log.Info($"Loaded {_flags.Count} flags");
        }
        catch (Exception ex) { _log.Error("Load: " + ex.Message); }
    }
}

static class Program
{
    [STAThread]
    static void Main()
    {
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? "",
                    Verb = "runas",
                    UseShellExecute = true
                });
            }
            catch { }
            return;
        }
        if (!Environment.Is64BitProcess) { MessageBox.Show("64-bit build required.", "Architecture Mismatch"); return; }
        using var mtx = new Mutex(true, $"Local\\FlagInjectorCS_{Environment.UserName}", out bool created);
        if (!created) { MessageBox.Show("Already running."); return; }
        try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.AboveNormal; } catch { }
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }
}
