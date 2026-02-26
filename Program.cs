using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

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
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct MODENTRY
{
    public uint dwSize;
    public uint modID;
    public uint procID;
    public uint glblCnt;
    public uint procCnt;
    public IntPtr modBaseAddr;
    public uint modBaseSize;
    public IntPtr hModule;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
}

sealed class MemEngine : IDisposable
{
    IntPtr _h, _base;
    int _pid;
    readonly object _lk = new();
    public bool On => _h != IntPtr.Zero && _base != IntPtr.Zero;
    public int Pid => _pid;
    public long Base => _base.ToInt64();
    public event Action<string>? Log;

    public bool Attach(int pid, string mod = "RobloxPlayerBeta.exe")
    {
        lock (_lk)
        {
            Detach();
            var h = W32.OpenProcess(W32.ACCESS, false, pid);
            if (h == IntPtr.Zero) { Log?.Invoke($"OpenProcess err {Marshal.GetLastWin32Error()}"); return false; }
            IntPtr b = IntPtr.Zero;
            for (int i = 0; i < 40 && b == IntPtr.Zero; i++) { b = FindMod(pid, mod); if (b == IntPtr.Zero) Thread.Sleep(200); }
            if (b == IntPtr.Zero) { W32.CloseHandle(h); Log?.Invoke("Base not found"); return false; }
            _h = h; _base = b; _pid = pid;
            Log?.Invoke($"Attached PID {pid} base 0x{b.ToInt64():X}");
            return true;
        }
    }

    public void Detach() { lock (_lk) { if (_h != IntPtr.Zero) W32.CloseHandle(_h); _h = _base = IntPtr.Zero; _pid = 0; } }
    public bool Alive() { lock (_lk) { return _h != IntPtr.Zero && W32.GetExitCodeProcess(_h, out uint c) && c == W32.ALIVE; } }

    static IntPtr FindMod(int pid, string name)
    {
        IntPtr s = IntPtr.Zero;
        try
        {
            s = W32.CreateToolhelp32Snapshot(W32.SNAP, (uint)pid);
            if (s == IntPtr.Zero || s == (IntPtr)(-1)) return IntPtr.Zero;
            var me = new MODENTRY { dwSize = (uint)Marshal.SizeOf<MODENTRY>() };
            if (!W32.Module32FirstW(s, ref me)) return IntPtr.Zero;
            do { if (me.szModule.Equals(name, StringComparison.OrdinalIgnoreCase)) return me.modBaseAddr; } while (W32.Module32NextW(s, ref me));
        }
        catch { }
        finally { if (s != IntPtr.Zero && s != (IntPtr)(-1)) W32.CloseHandle(s); }
        return IntPtr.Zero;
    }

    public bool WriteV(long off, byte[] data, int tries = 5, int delayMs = 60)
    {
        lock (_lk)
        {
            if (!On) return false;
            var addr = (IntPtr)(_base.ToInt64() + off);
            for (int t = 0; t < tries; t++)
            {
                if (t > 0) Thread.Sleep(delayMs);
                if (!W32.WriteProcessMemory(_h, addr, data, data.Length, out int w) || w != data.Length) continue;
                var chk = new byte[data.Length];
                if (!W32.ReadProcessMemory(_h, addr, chk, chk.Length, out int r) || r != chk.Length) continue;
                if (data.SequenceEqual(chk)) return true;
            }
            return false;
        }
    }

    public byte[]? Read(long off, int n)
    {
        lock (_lk)
        {
            if (!On) return null;
            var buf = new byte[n];
            return W32.ReadProcessMemory(_h, (IntPtr)(_base.ToInt64() + off), buf, n, out int r) && r == n ? buf : null;
        }
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

    public static string DetectPrefix(string name)
    {
        foreach (var p in _prefixes)
            if (name.Length > p.Length
                && name.StartsWith(p, StringComparison.OrdinalIgnoreCase)
                && char.IsUpper(name[p.Length]))
                return p;
        return "";
    }
}

sealed class OffsetStore
{
    readonly Dictionary<string, long> _map = new();
    readonly Dictionary<string, string> _ci = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, string> _norm = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, string> _stripped = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, string> _strippedNorm = new(StringComparer.OrdinalIgnoreCase);
    readonly List<string> _names = new();
    public IReadOnlyDictionary<string, long> Map => _map;
    public IReadOnlyList<string> Names => _names;
    public int Count => _map.Count;
    public string Cache { get; set; } = "";
    public string Url { get; set; } = "https://imtheo.lol/Offsets/FFlags.hpp";
    public event Action<string>? Log;

    public bool Fetch()
    {
        string? body = null; bool cached = false;
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            body = http.GetStringAsync(Url).GetAwaiter().GetResult();
            if (!string.IsNullOrEmpty(Cache) && !string.IsNullOrEmpty(body))
                try { Directory.CreateDirectory(Path.GetDirectoryName(Cache)!); File.WriteAllText(Cache, body, Encoding.UTF8); } catch { }
        }
        catch (Exception ex)
        {
            Log?.Invoke("Net: " + ex.Message);
            if (File.Exists(Cache)) try { body = File.ReadAllText(Cache); cached = true; } catch { }
        }
        if (string.IsNullOrEmpty(body)) { Log?.Invoke("No offset data"); return false; }
        var ns = Regex.Match(body, @"namespace FFlags\s*\{([^}]+)\}", RegexOptions.Singleline);
        if (!ns.Success) { Log?.Invoke("Namespace not found"); return false; }
        _map.Clear(); _ci.Clear(); _norm.Clear(); _stripped.Clear(); _strippedNorm.Clear(); _names.Clear();
        foreach (Match m in Regex.Matches(ns.Groups[1].Value, @"uintptr_t\s+(\w+)\s*=\s*(0x[0-9A-Fa-f]+);"))
        {
            if (!long.TryParse(m.Groups[2].Value.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long v)) continue;
            string n = m.Groups[1].Value;
            _map[n] = v;
            _ci[n] = n;
            string nNorm = n.Replace("_", "");
            if (!_norm.ContainsKey(nNorm)) _norm[nNorm] = n;
            string s = FlagPrefix.Strip(n);
            if (!_stripped.ContainsKey(s)) _stripped[s] = n;
            string sNorm = s.Replace("_", "");
            if (!_strippedNorm.ContainsKey(sNorm)) _strippedNorm[sNorm] = n;
            _names.Add(n);
        }
        Log?.Invoke($"{_map.Count} offsets{(cached ? " (cached)" : "")}");
        return _map.Count > 0;
    }

    public string? Resolve(string n)
    {
        if (_map.ContainsKey(n)) return n;
        if (_ci.TryGetValue(n, out var a)) return a;
        if (_norm.TryGetValue(n.Replace("_", ""), out var b)) return b;
        string s = FlagPrefix.Strip(n);
        if (s != n)
        {
            if (_ci.TryGetValue(s, out var c)) return c;
            if (_stripped.TryGetValue(s, out var d)) return d;
            string sNorm = s.Replace("_", "");
            if (_norm.TryGetValue(sNorm, out var e)) return e;
            if (_strippedNorm.TryGetValue(sNorm, out var f)) return f;
        }
        return null;
    }

    public long Offset(string resolved) => _map.TryGetValue(resolved, out long v) ? v : -1;
}

enum FType { Bool, Int, Float, String }

sealed class FlagEntry
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public FType Type { get; set; }
    public bool Enabled { get; set; } = true;
    public string Status { get; set; } = "";

    public byte[] GetBytes() => Type switch
    {
        FType.Bool => new[] { (byte)(Value.Equals("true", StringComparison.OrdinalIgnoreCase) || Value == "1" ? 1 : 0) },
        FType.Int => BitConverter.GetBytes(int.TryParse(Value, NumberStyles.Any, CultureInfo.InvariantCulture, out int iv) ? iv : 0),
        FType.Float => BitConverter.GetBytes(float.TryParse(Value, NumberStyles.Any, CultureInfo.InvariantCulture, out float fv) ? fv : 0f),
        _ => Encoding.UTF8.GetBytes(Value + '\0')
    };

    public int ByteLen() => Type switch { FType.Bool => 1, FType.Int => 4, FType.Float => 4, _ => Encoding.UTF8.GetByteCount(Value) + 1 };

    public static FType Infer(string v)
    {
        if (string.IsNullOrWhiteSpace(v)) return FType.String;
        string lv = v.Trim().ToLowerInvariant();
        if (lv is "true" or "false") return FType.Bool;
        if (int.TryParse(v, NumberStyles.Any, CultureInfo.InvariantCulture, out _)) return FType.Int;
        if (float.TryParse(v, NumberStyles.Any, CultureInfo.InvariantCulture, out _) && v.Contains('.')) return FType.Float;
        return FType.String;
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
}

sealed class DarkRenderer : ToolStripProfessionalRenderer
{
    protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e) =>
        e.Graphics.FillRectangle(new SolidBrush(Theme.Surface), e.AffectedBounds);

    protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
    {
        if (e.Item.Selected && e.Item.Enabled)
            using (var b = new SolidBrush(Theme.Hover)) e.Graphics.FillRectangle(b, new Rectangle(Point.Empty, e.Item.Size));
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
        using var p = new Pen(Theme.Border);
        e.Graphics.DrawLine(p, 4, y, e.Item.Width - 4, y);
    }

    protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
    {
        if (e.ToolStrip is StatusStrip) return;
        using var p = new Pen(Theme.Border);
        e.Graphics.DrawRectangle(p, e.AffectedBounds.X, e.AffectedBounds.Y, e.AffectedBounds.Width - 1, e.AffectedBounds.Height - 1);
    }
}

sealed class MainForm : Form
{
    readonly MemEngine _mem = new();
    readonly OffsetStore _off = new();
    readonly List<FlagEntry> _flags = new();
    readonly List<int> _modMap = new();
    readonly string _dir, _savePath;

    System.Windows.Forms.Timer _monTimer = new(), _wdTimer = new(), _graceTimer = new();
    NotifyIcon _tray = new();
    bool _autoApply = true, _watchdog = true, _realExit, _gameJoined;
    int _lastPid, _selMod = -1, _graceAttempts, _graceStableCount;
    string _selPreset = "";
    const int GraceIntervalMs = 1500;
    const int GraceMaxAttempts = 30;
    const int GraceStableNeeded = 6;

    SplitContainer _split = new();
    ListView _lvTop = new(), _lvBot = new();
    TextBox _searchTop = new(), _searchBot = new(), _edVal = new(), _edUpd = new();
    Label _lblTopHdr = new(), _lblBotHdr = new(), _lblSel = new(), _lblMod = new();
    Button _btnAdd = new(), _btnUpd = new(), _btnTog = new(), _btnRem = new();
    ToolStripStatusLabel _st1 = new(), _st2 = new(), _st3 = new();
    ContextMenuStrip _ctxTop = new(), _ctxBot = new();

    public MainForm()
    {
        _dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FlagInjectorCS");
        _savePath = Path.Combine(_dir, "flags.json");
        _off.Cache = Path.Combine(_dir, "offset_cache.hpp");
        Directory.CreateDirectory(_dir);

        Text = "FFlag Injector";
        Size = new Size(780, 740);
        MinimumSize = new Size(640, 520);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9f);
        BackColor = Theme.Bg;
        ForeColor = Theme.Fg;
        Icon = MakeIcon();
        AllowDrop = true;

        _mem.Log += s => BeginInvoke(() => Toast(s));
        _off.Log += s => BeginInvoke(() => SetStatus(2, s, Theme.Sub));
        LoadFlags();
        ThreadPool.QueueUserWorkItem(_ => { _off.Fetch(); BeginInvoke(() => { SetStatus(2, $"{_off.Count} offsets loaded", Theme.Green); RefreshTop(); RefreshBot(); }); });

        _monTimer.Interval = 500; _monTimer.Tick += (_, _) => Monitor(); _monTimer.Start();
        _wdTimer.Interval = 3000; _wdTimer.Tick += (_, _) => Watchdog(); _wdTimer.Start();
        _graceTimer.Interval = GraceIntervalMs; _graceTimer.Tick += (_, _) => GraceTick();

        DragEnter += (_, e) => { if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) e.Effect = DragDropEffects.Copy; };
        DragDrop += (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0
                && files[0].EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                ImportJson(files[0]);
        };

        SetupTray();
        BuildUI();
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
        return (Icon)Icon.FromHandle(h).Clone();
    }

    static void SetDouble(Control c)
    {
        typeof(Control).GetProperty("DoubleBuffered", BindingFlags.Instance | BindingFlags.NonPublic)?.SetValue(c, true);
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        int val = 1;
        W32.DwmSetWindowAttribute(Handle, 20, ref val, sizeof(int));
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        _split.SplitterDistance = (int)(ClientSize.Height * 0.45);
        FixCols();
        W32.SendMessage(_searchTop.Handle, 0x1501, (IntPtr)1, "Search available flags...");
        W32.SendMessage(_searchBot.Handle, 0x1501, (IntPtr)1, "Search modified flags...");
        W32.SendMessage(_edVal.Handle, 0x1501, (IntPtr)1, "Value");
        W32.SendMessage(_edUpd.Handle, 0x1501, (IntPtr)1, "New value");
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
        _monTimer.Stop(); _wdTimer.Stop(); _graceTimer.Stop(); _tray.Visible = false; _tray.Dispose(); _mem.Dispose();
        base.OnFormClosing(e);
    }

    protected override bool ProcessCmdKey(ref Message msg, Keys keyData) => keyData switch
    {
        Keys.Control | Keys.Shift | Keys.A => Do(ApplyAll),
        Keys.Control | Keys.O => Do(() => ImportJson()),
        Keys.Control | Keys.S => Do(ExportJson),
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
        _st2.Spring = false; _st2.AutoSize = false; _st2.Width = 200; _st2.TextAlign = ContentAlignment.MiddleLeft;
        _st2.Text = "  Offsets: loading..."; _st2.ForeColor = Theme.Sub;
        _st3.Spring = true; _st3.TextAlign = ContentAlignment.MiddleLeft; _st3.Text = ""; _st3.ForeColor = Theme.Sub;
        status.Items.AddRange(new ToolStripItem[] { _st1, _st2, _st3 });

        var actPanel = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 44, Padding = new Padding(6, 6, 6, 4), BackColor = Theme.Surface };
        var btnApply = MakeBtn("\u25B6 Apply All", 110, true);
        var btnImp = MakeBtn("Import", 80);
        var btnExp = MakeBtn("Export", 80);
        var btnClear = MakeBtn("Clear All", 85);
        btnClear.ForeColor = Theme.Red; btnClear.FlatAppearance.BorderColor = Theme.Red;
        btnApply.Click += (_, _) => ApplyAll();
        btnImp.Click += (_, _) => ImportJson();
        btnExp.Click += (_, _) => ExportJson();
        btnClear.Click += (_, _) => RemoveAll();
        var chkAuto = new CheckBox { Text = "Auto-apply", Checked = true, AutoSize = true, ForeColor = Theme.Sub, Padding = new Padding(12, 7, 0, 0) };
        var chkWd = new CheckBox { Text = "Watchdog", Checked = true, AutoSize = true, ForeColor = Theme.Sub, Padding = new Padding(4, 7, 0, 0) };
        chkAuto.CheckedChanged += (_, _) => _autoApply = chkAuto.Checked;
        chkWd.CheckedChanged += (_, _) => { _watchdog = chkWd.Checked; _wdTimer.Enabled = chkWd.Checked; };
        actPanel.Controls.AddRange(new Control[] { btnApply, btnImp, btnExp, btnClear, chkAuto, chkWd });

        _split.Dock = DockStyle.Fill;
        _split.Orientation = Orientation.Horizontal;
        _split.BackColor = Theme.Border;
        _split.SplitterWidth = 3;
        _split.Panel1.BackColor = Theme.Bg;
        _split.Panel2.BackColor = Theme.Bg;

        _lblTopHdr = new Label { Text = "AVAILABLE FLAGS", Dock = DockStyle.Top, Height = 26, Padding = new Padding(6, 6, 0, 0), Font = new Font("Segoe UI Semibold", 9f), ForeColor = Theme.Sub, BackColor = Theme.Bg };
        _searchTop.Dock = DockStyle.Top; _searchTop.BackColor = Theme.Surface; _searchTop.ForeColor = Theme.Fg; _searchTop.BorderStyle = BorderStyle.FixedSingle;
        _searchTop.TextChanged += (_, _) => RefreshTop();

        _lvTop.Dock = DockStyle.Fill; _lvTop.View = View.Details; _lvTop.FullRowSelect = true; _lvTop.MultiSelect = false;
        _lvTop.OwnerDraw = true; _lvTop.HeaderStyle = ColumnHeaderStyle.Nonclickable;
        _lvTop.BackColor = Theme.Bg; _lvTop.ForeColor = Theme.Fg; _lvTop.BorderStyle = BorderStyle.None; _lvTop.HideSelection = false;
        _lvTop.Columns.Add("Flag Name", 600);
        _lvTop.SelectedIndexChanged += (_, _) => TopClick();
        _lvTop.DoubleClick += (_, _) => { TopClick(); if (_selPreset != "") _edVal.Focus(); };
        _lvTop.DrawColumnHeader += LvDrawHeader;
        _lvTop.DrawItem += LvDrawItem;
        _lvTop.DrawSubItem += LvDrawSub;
        SetDouble(_lvTop);

        _ctxTop.Renderer = new DarkRenderer(); _ctxTop.BackColor = Theme.Surface; _ctxTop.ForeColor = Theme.Fg;
        _ctxTop.Items.Add("Add selected flag", null, (_, _) => AddFlag());
        _ctxTop.Opening += (_, e) => { if (_selPreset == "" || _edVal.Text.Trim() == "") e.Cancel = true; };
        _lvTop.ContextMenuStrip = _ctxTop;

        var addRow = new Panel { Dock = DockStyle.Bottom, Height = 38, BackColor = Theme.Surface, Padding = new Padding(6, 4, 6, 4) };
        _lblSel = new Label { Text = "No flag selected", AutoSize = false, Width = 220, Height = 28, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.Sub, AutoEllipsis = true };
        _edVal.Width = 180; _edVal.BackColor = Theme.Bg; _edVal.ForeColor = Theme.Fg; _edVal.BorderStyle = BorderStyle.FixedSingle;
        _edVal.TextChanged += (_, _) => _btnAdd.Enabled = _selPreset != "" && _edVal.Text.Trim() != "";
        _edVal.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; AddFlag(); } };
        _btnAdd = MakeBtn("Add", 60); _btnAdd.Enabled = false; _btnAdd.Click += (_, _) => AddFlag();
        var addFlow = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, AutoSize = false };
        addFlow.Controls.AddRange(new Control[] { _lblSel, _edVal, _btnAdd });
        addRow.Controls.Add(addFlow);

        _split.Panel1.Controls.Add(_lvTop);
        _split.Panel1.Controls.Add(addRow);
        _split.Panel1.Controls.Add(_searchTop);
        _split.Panel1.Controls.Add(_lblTopHdr);

        _lblBotHdr = new Label { Text = "MODIFIED FLAGS", Dock = DockStyle.Top, Height = 26, Padding = new Padding(6, 6, 0, 0), Font = new Font("Segoe UI Semibold", 9f), ForeColor = Theme.Sub, BackColor = Theme.Bg };
        _searchBot.Dock = DockStyle.Top; _searchBot.BackColor = Theme.Surface; _searchBot.ForeColor = Theme.Fg; _searchBot.BorderStyle = BorderStyle.FixedSingle;
        _searchBot.TextChanged += (_, _) => RefreshBot();

        _lvBot.Dock = DockStyle.Fill; _lvBot.View = View.Details; _lvBot.FullRowSelect = true; _lvBot.MultiSelect = false;
        _lvBot.OwnerDraw = true; _lvBot.HeaderStyle = ColumnHeaderStyle.Nonclickable;
        _lvBot.BackColor = Theme.Bg; _lvBot.ForeColor = Theme.Fg; _lvBot.BorderStyle = BorderStyle.None; _lvBot.HideSelection = false;
        _lvBot.Columns.Add("Flag", 300); _lvBot.Columns.Add("Value", 100); _lvBot.Columns.Add("Type", 60); _lvBot.Columns.Add("Status", 100);
        _lvBot.SelectedIndexChanged += (_, _) => BotClick();
        _lvBot.KeyDown += (_, e) => { if (e.KeyCode == Keys.Delete) RemoveFlag(); };
        _lvBot.DrawColumnHeader += LvDrawHeader;
        _lvBot.DrawItem += LvDrawItem;
        _lvBot.DrawSubItem += LvDrawSub;
        SetDouble(_lvBot);

        _ctxBot.Renderer = new DarkRenderer(); _ctxBot.BackColor = Theme.Surface; _ctxBot.ForeColor = Theme.Fg;
        _ctxBot.Items.Add("Update value", null, (_, _) => UpdateFlag());
        _ctxBot.Items.Add("Toggle on/off", null, (_, _) => ToggleFlag());
        _ctxBot.Items.Add("-");
        _ctxBot.Items.Add("Remove", null, (_, _) => RemoveFlag());
        _ctxBot.Opening += (_, e) => { if (_selMod < 0) e.Cancel = true; };
        _lvBot.ContextMenuStrip = _ctxBot;

        var modRow = new Panel { Dock = DockStyle.Bottom, Height = 38, BackColor = Theme.Surface, Padding = new Padding(6, 4, 6, 4) };
        _lblMod = new Label { Text = "No flag selected", AutoSize = false, Width = 200, Height = 28, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Theme.Sub, AutoEllipsis = true };
        _edUpd.Width = 140; _edUpd.BackColor = Theme.Bg; _edUpd.ForeColor = Theme.Fg; _edUpd.BorderStyle = BorderStyle.FixedSingle;
        _edUpd.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; UpdateFlag(); } };
        _btnUpd = MakeBtn("Update", 70); _btnUpd.Enabled = false; _btnUpd.Click += (_, _) => UpdateFlag();
        _btnTog = MakeBtn("Disable", 75); _btnTog.Enabled = false; _btnTog.Click += (_, _) => ToggleFlag();
        _btnRem = MakeBtn("Remove", 70); _btnRem.Enabled = false; _btnRem.ForeColor = Theme.Red; _btnRem.FlatAppearance.BorderColor = Theme.Red;
        _btnRem.Click += (_, _) => RemoveFlag();
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
        using var bg = new SolidBrush(Theme.Surface);
        e.Graphics.FillRectangle(bg, e.Bounds);
        TextRenderer.DrawText(e.Graphics, e.Header!.Text, Font, e.Bounds, Theme.Sub,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.LeftAndRightPadding);
        using var pen = new Pen(Theme.Border);
        e.Graphics.DrawLine(pen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
    }

    void LvDrawItem(object? s, DrawListViewItemEventArgs e) { }

    void LvDrawSub(object? s, DrawListViewSubItemEventArgs e)
    {
        if (e.Item == null || e.SubItem == null) return;
        Color bg = e.Item.Selected ? Theme.Hover : (e.ItemIndex % 2 == 0 ? Theme.Bg : Theme.Row2);
        using (var brush = new SolidBrush(bg))
            e.Graphics.FillRectangle(brush, e.Bounds);
        var fg = e.Item.Selected ? Theme.Fg : e.Item.ForeColor;
        TextRenderer.DrawText(e.Graphics, e.SubItem.Text, Font, e.Bounds, fg,
            TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.LeftAndRightPadding);
    }

    void SetStatus(int idx, string txt, Color? col = null)
    {
        if (InvokeRequired) { BeginInvoke(() => SetStatus(idx, txt, col)); return; }
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
        var t = new System.Windows.Forms.Timer { Interval = ms };
        t.Tick += (_, _) => { t.Stop(); t.Dispose(); SetStatus(3, "", Theme.Sub); };
        t.Start();
    }

    bool IsProcessWindow(int pid)
    {
        try
        {
            foreach (var p in Process.GetProcessesByName("RobloxPlayerBeta"))
                if (p.Id == pid && p.MainWindowHandle != IntPtr.Zero && !p.HasExited)
                    return true;
        }
        catch { }
        return false;
    }

    void Monitor()
    {
        int pid = 0;
        try { var p = Process.GetProcessesByName("RobloxPlayerBeta"); if (p.Length > 0) pid = p[0].Id; } catch { }
        if (pid != 0 && pid != _lastPid)
        {
            _lastPid = pid;
            _gameJoined = false;
            _graceTimer.Stop();
            SetStatus(1, $"Attaching PID {pid}...", Theme.Yellow);
            ThreadPool.QueueUserWorkItem(_ =>
            {
                if (_mem.Attach(pid))
                    BeginInvoke(() =>
                    {
                        SetStatus(1, $"PID {pid} \u2014 0x{_mem.Base:X}", Theme.Green);
                        _tray.Text = $"FFlag Injector \u2014 PID {pid}";
                        if (_autoApply && _off.Count > 0)
                            StartGrace();
                    });
                else BeginInvoke(() => SetStatus(1, "Attach failed", Theme.Red));
            });
        }
        else if (pid == 0 && _lastPid != 0)
        {
            _graceTimer.Stop();
            _gameJoined = false;
            _mem.Detach();
            _lastPid = 0;
            SetStatus(1, "Not detected", Theme.Red);
            _tray.Text = "FFlag Injector";
            Toast("Roblox disconnected");
        }
        else if (pid != 0 && !_mem.Alive())
        {
            _graceTimer.Stop();
            _gameJoined = false;
            _mem.Detach();
            _lastPid = 0;
            SetStatus(1, "Process exited", Theme.Red);
        }
    }

    void StartGrace()
    {
        _graceTimer.Stop();
        _graceAttempts = 0;
        _graceStableCount = 0;
        _gameJoined = false;
        SetStatus(3, "Waiting for game join...", Theme.Yellow);
        _graceTimer.Start();
    }

    void GraceTick()
    {
        _graceAttempts++;

        if (!_mem.On || !_mem.Alive())
        {
            _graceTimer.Stop();
            _gameJoined = false;
            return;
        }

        bool windowReady = IsProcessWindow(_mem.Pid);

        if (windowReady)
            _graceStableCount++;
        else
            _graceStableCount = 0;

        if (_graceStableCount >= GraceStableNeeded)
        {
            _graceTimer.Stop();
            _gameJoined = true;
            if (_mem.On && _autoApply && _off.Count > 0)
            {
                SetStatus(3, "Game joined, applying flags...", Theme.Green);
                ApplyAll();
            }
            return;
        }

        if (_graceAttempts >= GraceMaxAttempts)
        {
            _graceTimer.Stop();
            _gameJoined = true;
            if (_mem.On && _autoApply && _off.Count > 0)
            {
                SetStatus(3, "Grace timeout, applying flags...", Theme.Yellow);
                ApplyAll();
            }
            return;
        }

        string phase = windowReady
            ? $"Stabilizing {_graceStableCount}/{GraceStableNeeded}"
            : "Waiting for window";
        SetStatus(3, $"Grace {_graceAttempts}/{GraceMaxAttempts}: {phase}...", Theme.Yellow);
    }

    void Watchdog()
    {
        if (!_watchdog || !_gameJoined || !_mem.On || _off.Count == 0) return;
        ThreadPool.QueueUserWorkItem(_ =>
        {
            if (!_gameJoined) return;
            int fix = 0;
            foreach (var f in _flags.ToArray())
            {
                if (!f.Enabled) continue;
                var r = _off.Resolve(f.Name); if (r == null) continue;
                long o = _off.Offset(r); if (o <= 0) continue;
                var want = f.GetBytes();
                var cur = _mem.Read(o, want.Length);
                if (cur != null && want.SequenceEqual(cur)) continue;
                if (_mem.WriteV(o, want)) fix++;
            }
            if (fix > 0) BeginInvoke(() => { Toast($"Watchdog re-applied {fix} flag(s)"); RefreshBot(); });
        });
    }

    void ApplyAll()
    {
        if (!_mem.On) { Toast("Roblox not attached"); return; }
        ThreadPool.QueueUserWorkItem(_ =>
        {
            int ok = 0, fail = 0, skip = 0, dis = 0;
            foreach (var f in _flags.ToArray())
            {
                if (!f.Enabled) { dis++; continue; }
                var r = _off.Resolve(f.Name);
                if (r == null) { f.Status = "No Offset"; skip++; continue; }
                long o = _off.Offset(r);
                if (o <= 0) { f.Status = "Bad Offset"; skip++; continue; }
                if (_mem.WriteV(o, f.GetBytes())) { f.Status = "Applied"; ok++; } else { f.Status = "Failed"; fail++; }
            }
            BeginInvoke(() => { RefreshBot(); Toast($"Applied:{ok}  Failed:{fail}  Skip:{skip}  Off:{dis}", 4000); });
        });
    }

    bool ApplySingle(FlagEntry f)
    {
        if (!_mem.On) return false;
        var r = _off.Resolve(f.Name); if (r == null) { f.Status = "No Offset"; return false; }
        long o = _off.Offset(r); if (o <= 0) { f.Status = "Bad Offset"; return false; }
        if (_mem.WriteV(o, f.GetBytes())) { f.Status = "Applied"; return true; }
        f.Status = "Failed"; return false;
    }

    void RefreshTop()
    {
        _lvTop.BeginUpdate(); _lvTop.Items.Clear();
        var existing = new HashSet<string>(_flags.Select(f => f.Name));
        string filter = _searchTop.Text; int count = 0;
        foreach (var n in _off.Names)
        {
            if (existing.Contains(n)) continue;
            if (filter.Length > 0 && n.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0
                && FlagPrefix.Strip(n).IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;
            _lvTop.Items.Add(new ListViewItem(n) { ForeColor = Theme.Fg });
            count++;
        }
        _lvTop.EndUpdate();
        _lblTopHdr.Text = $"AVAILABLE FLAGS ({count})";
        _selPreset = ""; _lblSel.Text = "No flag selected"; _btnAdd.Enabled = false;
    }

    void RefreshBot()
    {
        _lvBot.BeginUpdate(); _lvBot.Items.Clear(); _modMap.Clear(); _selMod = -1;
        string filter = _searchBot.Text;
        for (int i = 0; i < _flags.Count; i++)
        {
            var f = _flags[i];
            if (filter.Length > 0 && f.Name.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0
                && FlagPrefix.Strip(f.Name).IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0) continue;
            string st = f.Enabled ? (f.Status == "" ? "Active" : f.Status) : "Disabled";
            if (_off.Count > 0 && _off.Resolve(f.Name) == null) st = "No Offset";
            var item = new ListViewItem(new[] { f.Name, f.Value, f.Type.ToString(), st });
            if (!f.Enabled) item.ForeColor = Theme.Border;
            else if (st == "Applied") item.ForeColor = Theme.Green;
            else if (st == "Failed") item.ForeColor = Theme.Red;
            else if (st == "No Offset") item.ForeColor = Theme.Peach;
            else item.ForeColor = Theme.Fg;
            _lvBot.Items.Add(item); _modMap.Add(i);
        }
        _lvBot.EndUpdate();
        _lblBotHdr.Text = $"MODIFIED FLAGS ({_flags.Count})";
        _lblMod.Text = "No flag selected"; _edUpd.Text = "";
        _btnUpd.Enabled = _btnTog.Enabled = _btnRem.Enabled = false;
    }

    void TopClick()
    {
        if (_lvTop.SelectedItems.Count == 0) { _selPreset = ""; _lblSel.Text = "No flag selected"; _btnAdd.Enabled = false; return; }
        _selPreset = _lvTop.SelectedItems[0].Text;
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
        if (_flags.Any(f => f.Name == _selPreset)) { Toast($"'{_selPreset}' already exists"); return; }
        var t = FlagEntry.Infer(v);
        if (t == FType.Int && !int.TryParse(v, NumberStyles.Any, CultureInfo.InvariantCulture, out _)) { Toast("Invalid integer"); return; }
        if (t == FType.Float && !float.TryParse(v, NumberStyles.Any, CultureInfo.InvariantCulture, out _)) { Toast("Invalid float"); return; }
        var fe = new FlagEntry { Name = _selPreset, Value = v, Type = t };
        _flags.Add(fe); SaveFlags(); RefreshTop(); RefreshBot(); _edVal.Text = "";
        if (_autoApply && _gameJoined && _mem.On)
            ThreadPool.QueueUserWorkItem(_ => { ApplySingle(fe); BeginInvoke(() => RefreshBot()); });
        Toast($"Added: {fe.Name} = {v} [{t}]");
    }

    void UpdateFlag()
    {
        if (_selMod < 0 || _selMod >= _flags.Count) return;
        string nv = _edUpd.Text.Trim();
        if (nv == "") { Toast("Value cannot be empty"); return; }
        var f = _flags[_selMod]; var nt = FlagEntry.Infer(nv);
        if (nt == FType.Int && !int.TryParse(nv, NumberStyles.Any, CultureInfo.InvariantCulture, out _)) { Toast("Invalid integer"); return; }
        if (nt == FType.Float && !float.TryParse(nv, NumberStyles.Any, CultureInfo.InvariantCulture, out _)) { Toast("Invalid float"); return; }
        f.Value = nv; f.Type = nt;
        if (f.Enabled && _gameJoined && _mem.On)
            ThreadPool.QueueUserWorkItem(_ => { ApplySingle(f); BeginInvoke(() => RefreshBot()); });
        SaveFlags(); RefreshBot(); Toast($"Updated: {f.Name} = {nv}");
    }

    void ToggleFlag()
    {
        if (_selMod < 0 || _selMod >= _flags.Count) return;
        var f = _flags[_selMod]; f.Enabled = !f.Enabled;
        SaveFlags(); RefreshBot(); Toast($"{(f.Enabled ? "Enabled" : "Disabled")}: {f.Name}");
    }

    void RemoveFlag()
    {
        if (_selMod < 0 || _selMod >= _flags.Count) return;
        string n = _flags[_selMod].Name; _flags.RemoveAt(_selMod); _selMod = -1;
        SaveFlags(); RefreshTop(); RefreshBot(); Toast($"Removed: {n}");
    }

    void RemoveAll()
    {
        if (_flags.Count == 0) return;
        if (MessageBox.Show($"Remove all {_flags.Count} flags?", "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        _flags.Clear(); _selMod = -1; SaveFlags(); RefreshTop(); RefreshBot(); Toast("All flags removed");
    }

    void ImportJson(string? path = null)
    {
        if (path == null) { using var dlg = new OpenFileDialog { Filter = "JSON|*.json", Title = "Import FFlags JSON" }; if (dlg.ShowDialog() != DialogResult.OK) return; path = dlg.FileName; }
        if (_off.Count == 0) { Toast("Offsets not loaded yet"); return; }
        try
        {
            string raw = File.ReadAllText(path, Encoding.UTF8);
            if (raw.Length > 0 && raw[0] == '\uFEFF') raw = raw[1..];
            var existing = new Dictionary<string, int>();
            for (int i = 0; i < _flags.Count; i++) existing[_flags[i].Name] = i;
            int added = 0, updated = 0, skipped = 0;
            foreach (Match m in Regex.Matches(raw, @"""((?:[^""\\]|\\.)*)\""\s*:\s*(?:""((?:[^""\\]|\\.)*)""|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(\btrue\b|\bfalse\b))"))
            {
                string jn = JsonUnescape(m.Groups[1].Value); string val;
                if (m.Groups[2].Success) val = JsonUnescape(m.Groups[2].Value);
                else if (m.Groups[3].Success) val = m.Groups[3].Value;
                else if (m.Groups[4].Success) val = m.Groups[4].Value;
                else continue;
                var r = _off.Resolve(jn); if (r == null) { skipped++; continue; }
                var t = FlagEntry.Infer(val);
                if (existing.TryGetValue(r, out int idx)) { _flags[idx].Value = val; _flags[idx].Type = t; _flags[idx].Enabled = true; updated++; }
                else { _flags.Add(new FlagEntry { Name = r, Value = val, Type = t }); existing[r] = _flags.Count - 1; added++; }
            }
            if (added + updated == 0) { Toast($"No matching flags ({skipped} skipped)"); return; }
            SaveFlags(); RefreshTop(); RefreshBot();
            if (_autoApply && _gameJoined && _mem.On) ApplyAll();
            Toast($"Imported: +{added} ~{updated} skip:{skipped}");
        }
        catch (Exception ex) { Toast("Import error: " + ex.Message); }
    }

    void ExportJson()
    {
        if (_flags.Count == 0) { Toast("No flags to export"); return; }
        using var dlg = new SaveFileDialog { Filter = "JSON|*.json", FileName = "flags.json" };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        try
        {
            var sb = new StringBuilder("{\n");
            for (int i = 0; i < _flags.Count; i++)
            {
                var f = _flags[i]; string k = JsonEscape(f.Name);
                string entry = f.Type switch
                {
                    FType.Bool => $"  \"{k}\": {(f.Value.Equals("true", StringComparison.OrdinalIgnoreCase) || f.Value == "1" ? "true" : "false")}",
                    FType.Int => int.TryParse(f.Value, out int iv) ? $"  \"{k}\": {iv}" : $"  \"{k}\": \"{JsonEscape(f.Value)}\"",
                    FType.Float => float.TryParse(f.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out float fv) ? $"  \"{k}\": {fv.ToString("G", CultureInfo.InvariantCulture)}" : $"  \"{k}\": \"{JsonEscape(f.Value)}\"",
                    _ => $"  \"{k}\": \"{JsonEscape(f.Value)}\""
                };
                sb.Append(entry); if (i < _flags.Count - 1) sb.Append(','); sb.Append('\n');
            }
            sb.Append('}');
            File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(false));
            Toast($"Exported {_flags.Count} flags");
        }
        catch (Exception ex) { Toast("Export error: " + ex.Message); }
    }

    void SaveFlags()
    {
        try
        {
            var sb = new StringBuilder("[");
            for (int i = 0; i < _flags.Count; i++)
            {
                var f = _flags[i];
                sb.Append($"{{\"n\":\"{JsonEscape(f.Name)}\",\"v\":\"{JsonEscape(f.Value)}\",\"t\":\"{f.Type}\",\"e\":{(f.Enabled ? "true" : "false")}}}");
                if (i < _flags.Count - 1) sb.Append(',');
            }
            sb.Append(']');
            string tmp = _savePath + ".tmp";
            File.WriteAllText(tmp, sb.ToString(), new UTF8Encoding(false));
            File.Move(tmp, _savePath, true);
        }
        catch (Exception ex) { Toast("Save error: " + ex.Message); }
    }

    void LoadFlags()
    {
        if (!File.Exists(_savePath)) return;
        try
        {
            string raw = File.ReadAllText(_savePath, Encoding.UTF8);
            if (raw.Length > 0 && raw[0] == '\uFEFF') raw = raw[1..];
            foreach (Match m in Regex.Matches(raw, @"\{""n"":""((?:[^""\\]|\\.)*)"",""v"":""((?:[^""\\]|\\.)*)"",""t"":""(\w+)"",""e"":(true|false)\}"))
            {
                Enum.TryParse<FType>(m.Groups[3].Value, true, out var t);
                _flags.Add(new FlagEntry { Name = JsonUnescape(m.Groups[1].Value), Value = JsonUnescape(m.Groups[2].Value), Type = t, Enabled = m.Groups[4].Value == "true" });
            }
        }
        catch { }
    }

    static string JsonEscape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");

    static string JsonUnescape(string s)
    {
        const char ph = '\uFFFF';
        s = s.Replace("\\\\", ph.ToString());
        s = s.Replace("\\\"", "\"").Replace("\\n", "\n").Replace("\\r", "\r").Replace("\\t", "\t").Replace("\\/", "/");
        return s.Replace(ph, '\\');
    }
}

static class Program
{
    [STAThread]
    static void Main()
    {
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
        {
            try { Process.Start(new ProcessStartInfo { FileName = Environment.ProcessPath!, Verb = "runas", UseShellExecute = true }); } catch { }
            return;
        }
        if (!Environment.Is64BitProcess) { MessageBox.Show("64-bit build required.", "Architecture Mismatch"); return; }
        using var mtx = new Mutex(true, "FlagInjectorCS_SingleInstance", out bool created);
        if (!created) { MessageBox.Show("Already running."); return; }
        try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.AboveNormal; } catch { }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
    }
}
