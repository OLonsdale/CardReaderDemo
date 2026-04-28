using System.Text;
using PCSC;
using PCSC.Iso7816;
using PCSC.Monitoring;

namespace CardReaderDemo;

public sealed class CardReaderService : IDisposable
{
    private readonly IContextFactory _contextFactory = ContextFactory.Instance;
    private ISCardMonitor? _monitor;

    public Action<string>? OnCardInserted { get; set; }
    public Action<string>? OnCardRemoved { get; set; }

    private static readonly byte[][] KnownAids =
    [
        HexBytes("A0000000031010"),
        HexBytes("A0000000032010"),
        HexBytes("A0000000041010"),
        HexBytes("A0000000043060"),
        HexBytes("A00000002501"),
        HexBytes("A0000001523010")
    ];

    public void StartMonitoring()
    {
        if (_monitor != null)
            return;

        using var context = _contextFactory.Establish(SCardScope.System);
        var readers = context.GetReaders();

        if (readers.Length == 0)
            throw new InvalidOperationException("No smart card readers found.");

        _monitor = MonitorFactory.Instance.Create(SCardScope.System);

        _monitor.CardInserted += async (_, args) =>
        {
            await Task.Delay(900);
            OnCardInserted?.Invoke(args.ReaderName);
        };

        _monitor.CardRemoved += (_, args) =>
        {
            OnCardRemoved?.Invoke(args.ReaderName);
        };

        _monitor.Start(readers);
    }

    public void StopMonitoring()
    {
        _monitor?.Cancel();
        _monitor?.Dispose();
        _monitor = null;
    }

    public CardInfo GetCardInfo(string? readerName = null)
    {
        using var context = _contextFactory.Establish(SCardScope.System);
        var readers = context.GetReaders();

        if (readers.Length == 0)
            return new CardInfo { Error = "No smart card readers found." };

        readerName ??= readers[0];

        try
        {
            using var isoReader = new IsoReader(
                context,
                readerName,
                SCardShareMode.Shared,
                SCardProtocol.Any,
                false);

            var info = new CardInfo
            {
                ReaderName = readerName,
                Atr = GetAtr(context, readerName),
                Protocol = isoReader.ActiveProtocol.ToString()
            };

            var selectedApp = SelectPaymentApplication(isoReader);

            if (selectedApp == null)
            {
                info.Error = "No payment application found.";
                return info;
            }

            info.Aid = Hex(selectedApp.Aid);
            info.CardType = DetectCardType(selectedApp.Aid);
            info.ApplicationLabel = ReadTextTag(selectedApp.Fci, "50");
            info.ApplicationPreferredName = ReadTextTag(selectedApp.Fci, "9F12");
            info.Pdol = Hex(FindTag(selectedApp.Fci, "9F38") ?? []);

            var gpo = GetProcessingOptions(isoReader, selectedApp.Fci);

            if (gpo == null)
            {
                info.Error = "GPO failed.";
                return info;
            }

            info.GpoRaw = Hex(gpo);

            var afl = ParseAfl(gpo);

            if (afl.Count == 0)
            {
                info.Error = "No AFL found in GPO response.";
                return info;
            }

            foreach (var item in afl)
            {
                for (var record = item.StartRecord; record <= item.EndRecord; record++)
                {
                    var recordData = ReadRecord(isoReader, item.Sfi, record);

                    if (recordData == null)
                        continue;

                    info.RawRecords.Add(Hex(recordData));

                    info.Pan ??= ReadPan(recordData);
                    info.Expiry ??= ReadExpiry(recordData);
                    info.CardholderName ??= ReadTextTag(recordData, "5F20");
                    info.IssuerCountryCode ??= ReadNumericTag(recordData, "5F28");
                    info.ServiceCode ??= ReadServiceCode(recordData);

                    if (info.Pan != null && info.Expiry != null)
                        return info;
                }
            }

            return info;
        }
        catch (Exception ex)
        {
            return new CardInfo
            {
                ReaderName = readerName,
                Error = ex.Message
            };
        }
    }

    public string? GetPan(string? readerName = null) => GetCardInfo(readerName).Pan;
    public string? GetExpiry(string? readerName = null) => GetCardInfo(readerName).Expiry;
    public string? GetCardType(string? readerName = null) => GetCardInfo(readerName).CardType;
    public string? GetAtr(string? readerName = null)
    {
        using var context = _contextFactory.Establish(SCardScope.System);
        var readers = context.GetReaders();

        if (readers.Length == 0)
            return null;

        return GetAtr(context, readerName ?? readers[0]);
    }

    public string? GetAid(string? readerName = null) => GetCardInfo(readerName).Aid;
    public string? GetApplicationLabel(string? readerName = null) => GetCardInfo(readerName).ApplicationLabel;
    public string? GetApplicationPreferredName(string? readerName = null) => GetCardInfo(readerName).ApplicationPreferredName;
    public string? GetCardholderName(string? readerName = null) => GetCardInfo(readerName).CardholderName;

    private static string? GetAtr(ISCardContext context, string readerName)
    {
        try
        {
            using var reader = context.ConnectReader(readerName, SCardShareMode.Shared, SCardProtocol.Any);
            var atr = reader.GetAttrib(SCardAttribute.AtrString);
            return atr is { Length: > 0 } ? Hex(atr) : null;
        }
        catch
        {
            return null;
        }
    }

    private static SelectedApplication? SelectPaymentApplication(IsoReader reader)
    {
        var pse = SelectDf(reader, "1PAY.SYS.DDF01");
        var aids = new List<byte[]>();

        if (pse != null)
        {
            foreach (var aid in FindTags(pse, "4F"))
                aids.Add(aid);
        }

        aids.AddRange(KnownAids);

        foreach (var aid in aids.DistinctBy(Hex))
        {
            var fci = SelectAid(reader, aid);

            if (fci != null)
                return new SelectedApplication(aid, fci);
        }

        return null;
    }

    private static byte[]? SelectDf(IsoReader reader, string name)
    {
        var apdu = new CommandApdu(IsoCase.Case3Short, reader.ActiveProtocol)
        {
            CLA = 0x00,
            INS = 0xA4,
            P1 = 0x04,
            P2 = 0x00,
            Data = Encoding.ASCII.GetBytes(name)
        };

        var response = reader.Transmit(apdu);
        return GetFullResponse(reader, response);
    }

    private static byte[]? SelectAid(IsoReader reader, byte[] aid)
    {
        var apdu = new CommandApdu(IsoCase.Case3Short, reader.ActiveProtocol)
        {
            CLA = 0x00,
            INS = 0xA4,
            P1 = 0x04,
            P2 = 0x00,
            Data = aid
        };

        var response = reader.Transmit(apdu);
        return GetFullResponse(reader, response);
    }

    private static byte[]? GetProcessingOptions(IsoReader reader, byte[] fci)
    {
        var pdol = FindTag(fci, "9F38");
        var data = BuildGpoData(pdol);

        var apdu = new CommandApdu(IsoCase.Case3Short, reader.ActiveProtocol)
        {
            CLA = 0x80,
            INS = 0xA8,
            P1 = 0x00,
            P2 = 0x00,
            Data = data
        };

        var response = reader.Transmit(apdu);
        return GetFullResponse(reader, response);
    }

    private static byte[] BuildGpoData(byte[]? pdol)
    {
        if (pdol == null || pdol.Length == 0)
            return [0x83, 0x00];

        var values = new List<byte>();
        var i = 0;

        while (i < pdol.Length)
        {
            var tag = ReadTag(pdol, ref i);
            var length = pdol[i++];

            values.AddRange(DefaultDdolValue(tag, length));
        }

        return [0x83, (byte)values.Count, .. values];
    }

    private static byte[] DefaultDdolValue(string tag, int length)
    {
        var value = new byte[length];

        switch (tag)
        {
            case "9F66":
                value = [0x36, 0x00, 0x00, 0x00];
                break;

            case "9F02":
            case "9F03":
                value = new byte[length];
                break;

            case "9F1A":
            case "5F2A":
                value = [0x08, 0x26];
                break;

            case "9A":
                var now = DateTime.Now;
                value = [(byte)(now.Year % 100), (byte)now.Month, (byte)now.Day];
                break;

            case "9C":
                value = [0x00];
                break;

            case "9F37":
                Random.Shared.NextBytes(value);
                break;
        }

        return value.Length == length ? value : value.Take(length).Concat(new byte[length - value.Length]).ToArray();
    }

    private static byte[]? ReadRecord(IsoReader reader, int sfi, int record)
    {
        var apdu = new CommandApdu(IsoCase.Case2Short, reader.ActiveProtocol)
        {
            CLA = 0x00,
            INS = 0xB2,
            P1 = (byte)record,
            P2 = (byte)((sfi << 3) | 4),
            Le = 0x00
        };

        var response = reader.Transmit(apdu);

        if (response.SW1 == 0x6C)
        {
            apdu.Le = response.SW2;
            response = reader.Transmit(apdu);
        }

        return response.SW1 == 0x90 && response.SW2 == 0x00
            ? response.GetData()
            : null;
    }

    private static List<AflItem> ParseAfl(byte[] gpo)
    {
        var afl = FindTag(gpo, "94");

        if (afl == null && gpo.Length >= 2 && gpo[0] == 0x80)
        {
            var length = gpo[1];

            if (gpo.Length >= 2 + length && length > 2)
                afl = gpo.Skip(4).Take(length - 2).ToArray();
        }

        var result = new List<AflItem>();

        if (afl == null)
            return result;

        for (var i = 0; i + 3 < afl.Length; i += 4)
        {
            result.Add(new AflItem(
                afl[i] >> 3,
                afl[i + 1],
                afl[i + 2]));
        }

        return result;
    }

    private static string? ReadPan(byte[] data)
    {
        var pan = FindTag(data, "5A");

        if (pan != null)
            return TrimPan(Hex(pan));

        var track2 = FindTag(data, "57");

        if (track2 == null)
            return null;

        var raw = Hex(track2);
        var separator = raw.IndexOf('D');

        return separator > 0 ? TrimPan(raw[..separator]) : null;
    }

    private static string? ReadExpiry(byte[] data)
    {
        var expiry = FindTag(data, "5F24");

        if (expiry is { Length: >= 2 })
            return $"20{expiry[0]:X2}/{expiry[1]:X2}";

        var track2 = FindTag(data, "57");

        if (track2 == null)
            return null;

        var raw = Hex(track2);
        var separator = raw.IndexOf('D');

        if (separator < 0 || raw.Length < separator + 5)
            return null;

        return $"20{raw.Substring(separator + 1, 2)}/{raw.Substring(separator + 3, 2)}";
    }

    private static string? ReadServiceCode(byte[] data)
    {
        var track2 = FindTag(data, "57");

        if (track2 == null)
            return null;

        var raw = Hex(track2);
        var separator = raw.IndexOf('D');

        if (separator < 0 || raw.Length < separator + 8)
            return null;

        return raw.Substring(separator + 5, 3);
    }

    private static string? ReadTextTag(byte[] data, string tag)
    {
        var value = FindTag(data, tag);
        return value == null ? null : Encoding.ASCII.GetString(value).Trim();
    }

    private static string? ReadNumericTag(byte[] data, string tag)
    {
        var value = FindTag(data, tag);
        return value == null ? null : Hex(value);
    }

    private static byte[]? GetFullResponse(IsoReader reader, Response response)
    {
        var data = response.GetData() ?? [];

        while (response.SW1 == 0x61)
        {
            var getResponse = new CommandApdu(IsoCase.Case2Short, reader.ActiveProtocol)
            {
                CLA = 0x00,
                INS = 0xC0,
                P1 = 0x00,
                P2 = 0x00,
                Le = response.SW2 == 0x00 ? 0x00 : response.SW2
            };

            response = reader.Transmit(getResponse);
            data = [.. data, .. response.GetData() ?? []];
        }

        if (response.SW1 == 0x90 && response.SW2 == 0x00)
            return data;

        return null;
    }

    private static byte[]? FindTag(byte[] data, string wantedTag)
    {
        return FindTags(data, wantedTag).FirstOrDefault();
    }

    private static List<byte[]> FindTags(byte[] data, string wantedTag)
    {
        var results = new List<byte[]>();
        ReadTlv(data, wantedTag, results);
        return results;
    }

    private static void ReadTlv(byte[] data, string wantedTag, List<byte[]> results)
    {
        var i = 0;

        while (i < data.Length)
        {
            var start = i;
            var tag = ReadTag(data, ref i);

            if (i >= data.Length)
                return;

            var length = ReadLength(data, ref i);

            if (length < 0 || i + length > data.Length)
                return;

            var value = data.Skip(i).Take(length).ToArray();

            if (tag == wantedTag)
                results.Add(value);

            if (IsConstructed(data[start]))
                ReadTlv(value, wantedTag, results);

            i += length;
        }
    }

    private static string ReadTag(byte[] data, ref int i)
    {
        var tag = new List<byte> { data[i++] };

        if ((tag[0] & 0x1F) == 0x1F)
        {
            while (i < data.Length)
            {
                var next = data[i++];
                tag.Add(next);

                if ((next & 0x80) == 0)
                    break;
            }
        }

        return Hex(tag.ToArray());
    }

    private static int ReadLength(byte[] data, ref int i)
    {
        if (i >= data.Length)
            return -1;

        int length = data[i++];

        if ((length & 0x80) == 0)
            return length;

        var byteCount = length & 0x7F;
        length = 0;

        for (var x = 0; x < byteCount; x++)
        {
            if (i >= data.Length)
                return -1;

            length = (length << 8) | data[i++];
        }

        return length;
    }

    private static bool IsConstructed(byte tagByte) => (tagByte & 0x20) == 0x20;

    private static string DetectCardType(byte[] aid)
    {
        var hex = Hex(aid);

        if (hex.StartsWith("A000000003")) return "Visa";
        if (hex.StartsWith("A000000004")) return "Mastercard";
        if (hex.StartsWith("A000000025")) return "American Express";
        if (hex.StartsWith("A000000152")) return "Discover / Diners";

        return "Unknown";
    }

    private static string TrimPan(string value) => value.TrimEnd('F');

    private static string Hex(byte[] data) =>
        BitConverter.ToString(data).Replace("-", "");

    private static byte[] HexBytes(string hex) =>
        Enumerable.Range(0, hex.Length / 2)
            .Select(i => Convert.ToByte(hex.Substring(i * 2, 2), 16))
            .ToArray();

    public void Dispose()
    {
        StopMonitoring();
    }

    private sealed record SelectedApplication(byte[] Aid, byte[] Fci);

    private sealed record AflItem(int Sfi, int StartRecord, int EndRecord);
}

public sealed class CardInfo
{
    public string? ReaderName { get; set; }
    public string? Protocol { get; set; }
    public string? Atr { get; set; }
    public string? CardType { get; set; }
    public string? Aid { get; set; }
    public string? ApplicationLabel { get; set; }
    public string? ApplicationPreferredName { get; set; }
    public string? Pan { get; set; }
    public string? Expiry { get; set; }
    public string? CardholderName { get; set; }
    public string? IssuerCountryCode { get; set; }
    public string? ServiceCode { get; set; }
    public string? Pdol { get; set; }
    public string? GpoRaw { get; set; }
    public string? Error { get; set; }
    public List<string> RawRecords { get; set; } = [];
}